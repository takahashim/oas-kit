def circular_clone(obj)
  Marshal.load(Marshal.dump(obj))
end

def hash_traverse(hash, key_path: nil, &proc)
  key_path ||= []

  hash.each_pair do |key, val|
    key_path << key
    proc.call(key, val, key_path.join('/'))

    if val.is_a?(Hash)
      hash_traverse(val, key_path: key_path, &proc)
    end

    key_path.pop
  end
end

def fix_up_sub_schema(schema, parent, options)
  if schema[:nullable]
    # options.patches+=1
  end

  if schema[:discriminator].is_a?(String)
    schema[:discriminator] = { propertyName: schema[:discriminator] }
  end

  if schema[:items].is_a?(Array)
    if schema[:items].empty?
      schema[:items] = {}
    elsif schema[:items].length == 1
      schema[:items] = schema[:items][0]
    else
      schema[:items] = { anyOf: schema[:items] }
    end
  end

  if schema[:type].is_a?(Array)

    ## scheme[:type] should not be Array
    if schema[:type].length == 0
      schema.delete :type
    elsif !schema[:oneOf]
      schema[:oneOf] = []
      schema[:type].each do |type|
        newSchema = {}
        if type == 'null'
          schema[:nullable] = true
        else
          newSchema[:type] = type
          common[:arrayProperties].each do |prop|
            if !schema[prop]
              newSchema[prop] = schema[prop]
              schema.delete prop
            end
          end
        end
        if newSchema[:type]
          schema[:oneOf].push(newSchema)
        end
      end

      schema.delete :type
      if schema[:oneOf].empty?
        schema.delete :oneOf ## means was just null => nullable
      elsif schema[:oneOf].length < 2
        schema[:type] = schema[:oneOf][0][:type]
        if schema[:oneOf][0].keys.length > 1
          warn "Lost properties from oneOf: #{schema[:oneOf]}"
        end
        schema.delete :oneOf
      end
    end

    ## do not else this
    if schema[:type].is_a?(Array) && schema[:type].length == 1
      schema[:type] = schema[:type][0]
    end
  end

  if schema[:type] == 'null'
    schema.delete :type
    schema[:nullable] = true
  end

  if schema[:type] == 'array'
    schema[:items] ||= {}
  end

  if schema[:type] == 'file'
    schema[:type] = 'string'
    schema[:format] = 'binary'
  end

  if schema[:required] == true || schema[:required] == false
    if schema[:required] && schema[:name]
      parent[:required] ||= []
      if parent[:required].is_a?(Array)
        parent[:required].push(schema[:name])
      end
    end
    schema.delete :required
  end

  ## TODO if we have a nested properties (object inside an object) and the
  ## *parent* type is not set, force it to object
  ## TODO if default is set but type is not set, force type to typeof default

  if schema[:xml] && schema[:xml][:namespace] == ''
      schema[:xml].delete :namespace
    end
  end

  if schema[:allowEmptyValue]
    schema.delete :allowEmptyValue
  end
end


def fix_up_sub_schema_extensions(schema, parent)
  if schema["x-required"].is_a?(Array)
    if (!schema[:required])
      schema[:required] = []
    end
    schema[:required] = schema[:required].concat(schema[:"x-required"])
    schema.delete :"x-required"
  end

  if schema[:"x-anyOf"]
    schema[:anyOf] = schema[:"x-anyOf"]
    schema.delete :"x-anyOf"
  end

  if schema[:"x-oneOf"]
    schema[:oneOf] = schema[:"x-oneOf"]
    schema.delete :"x-oneOf"
  end

  if schema[:"x-not"]
    schema[:not] = schema[:"x-not"]
    schema.delete :"x-not"
  end

  if schema[:"x-nullable"] == true || schema[:"x-nullable"] == false
    schema[:nullable] = schema[:"x-nullable"]
    schema.delete :"x-nullable"
  end

  if schema[:"x-discriminator"].is_a?(Hash) && schema[:"x-discriminator"][:propertyName].is_a?(String)
    schema[:discriminator] = schema[:"x-discriminator"]
    schema.delete :"x-discriminator"
    schema[:discriminator][:mapping].each do |entry|
      schemaOrRef = schema[:discriminator][:mapping][entry]
      if schemaOrRef.start_with? '#/definitions/'
        schema[:discriminator][:mapping][entry] = schemaOrRef.sub('#/definitions/', '#/components/schemas/')
      end
    end
  end
end

def fix_up_schema(schema, options)
  walk_schema(schema,{},{}) do |schema,parent,state|
    fix_up_sub_schema_extensions(schema,parent)
    fix_up_sub_schema(schema,parent,options)
  end
end

def getMiroComponentName(ref)
  if ref.index('#')
    ref = ref.split('#')[1].split('/').pop()
  else
    ref = ref.split('/').pop().split('.')[0]
  end

  encodeURIComponent(common.sanitise(ref))
}


def sanitise(s)
  s = s.gsub('[]','Array')
  components = s.split('/')
  components[0] = components[0].gsub(/[^A-Za-z0-9_\-\.]+|\s+/m, '_');

  components.join('/')
end

def fixupRefs(obj, key, state)
  options = state.payload.options
  if isRef(obj, key)
    if obj[key].start_with?('#/components/')
      ## no-op
    elsif obj[key] == '#/consumes'
      ## people are *so* creative
      obj.delete key
      state[:parent][state[:pkey]] = clone(options[:openapi][:consumes])
    elsif obj[key] == '#/produces'
      ## and by creative, I mean devious
      obj.delete key
      state[:parent][state[:pkey]] = clone(options[:openapi][:produces])
    elsif obj[key].start_with?('#/definitions/')
      ##only the first part of a schema component name must be sanitised
      keys = obj[key].sub('#/definitions/', '').split('/')
      ref = jptr.jp_unescape(keys[0])

      newKey = @componentNames[:schemas][URI.encode_www_form_component(ref)] ## lookup, resolves a $ref
      if newKey
        keys[0] = newKey
      else
        throwOrWarn('Could not resolve reference '+obj[key],obj,options)
      end
      obj[key] = '#/components/schemas/' + keys.join('/')
    elsif obj[key].start_with?('#/parameters/')
      ## for extensions like Apigee's x-templates
      obj[key] = '#/components/parameters/' + common.sanitise(obj[key].sub('#/parameters/', ''))
    elsif (obj[key].start_wWith?('#/responses/'))
      ## for extensions like Apigee's x-templates
      obj[key] = '#/components/responses/' + common.sanitise(obj[key].sub('#/responses/', ''))
    elsif obj[key].start_with?('#')
      ## fixes up direct $refs or those created by resolvers
      target = clone(jptr.jptr(options.openapi,obj[key]));
      if !target
        throwOrWarn('direct $ref not found '+obj[key],obj,options)
      elsif options[:refmap][obj[key]]
        obj[key] = options[:refmap][obj[key]]
      else
        ## we use a heuristic to determine what kind of thing is being referenced
        oldRef = obj[key]
        oldRef = oldRef.sub('/properties/headers/','')
        oldRef = oldRef.sub('/properties/responses/','')
        oldRef = oldRef.sub('/properties/parameters/','')
        oldRef = oldRef.sub('/properties/schemas/','')
        type = 'schemas'
        schemaIndex = oldRef.rindex('/schema')
        type = if oldRef.index('/headers/') > schemaIndex
                 'headers'
               elsif oldRef.index('/responses/') > schemaIndex
                 'responses'
               elsif oldRef.index('/example') > schemaIndex
                 'examples'
               elsif oldRef.index('/x-') > schemaIndex
                 'extensions'
               elsif oldRef.index('/parameters/') > schemaIndex
                 'parameters'
               else
                 'schemas'
               end

        ## non-body/form parameters have not moved in the overall structure (like responses)
        ## but extracting the requestBodies can cause the *number* of parameters to change

        if type == 'schemas'
          fixUpSchema(target, options)
        end

        if type != 'responses' && type != 'extensions'
          prefix = type[0, type.length]
          if prefix == 'parameter' && target[:name] && target[:name] == common.sanitise(target[:name])
            prefix = URI.encode_www_form_component(target[:name])
          end

          suffix = 1
          if obj[:'x-miro']
            prefix = getMiroComponentName(obj[:'x-miro'])
            suffix = nil
          end

          while jptr.jptr(options[:openapi], "\#/components/#{type}/#{prefix}#{suffix}")
            suffix = if suffix.nil?
                       2
                     else
                       suffix + 1
                     end
          end

          newRef = "\#/components/#{type}/#{prefix}#{suffix}"
          refSuffix = ''

          if type == 'examples'
            target = { value: target }
            refSuffix = '/value'
          end

          jptr.jptr(options[:openapi], newRef, target)
          options[:refmap][obj[key]] = newRef+refSuffix
          obj[key] = newRef+refSuffix
        end
      end
    end

    delete obj[:'x-miro']

    ## do this last - rework cases where $ref object has sibling properties
    if obj.keys.length > 1
      tmpRef = obj[key];
      inSchema = state[:path].index('/schema') >= 0 ## not perfect, but in the absence of a reasonably-sized and complete OAS 2.0 parser...
      if options[:refSiblings] == 'preserve'
      ## no-op
      elsif inSchema && options[:refSiblings] == :'allOf'
        delete obj[:"$ref"];
        state[:parent][state[:pkey]] = { allOf: [ { "$ref": tmpRef }, obj ]}
      else  ## remove, or not 'preserve' and not in a schema
        state[:parent][state[:pkey]] = { "$ref": tmpRef }
      end
    end
  end

  if key == :'x-ms-odata' && obj[key].is_a?(String) && obj[key].start_with?('#/')
    keys = obj[key].sub('#/definitions/', '').sub('#/components/schemas/','').split('/')
    newKey = @componentNames[:schemas][URI.decode_www_form_component(keys[0])] ## lookup, resolves a $ref
    if newKey
      keys[0] = newKey
    else
      raise "Could not resolve reference #{obj[key]}"
    end
    obj[key] = '#/components/schemas/' + keys.join('/')
  end
end

def isRef(obj, key)
  key == '$ref' && (obj && obj[key].is_a?(String))
end

def jp_escape(s)
  s.gsub(/\~/, '~0').gsub(/\//g, '~1')
end

def jp_unescape(s)
  s.gsub(/\~1/, '/').gsub(/~0/, '~')
end

# This has to happen as a separate pass because multiple $refs may point
# through elements of the same path
def dedupeRefs(openapi, options)
  options[:refmap].each do |ref|
    jptr.jptr(openapi, ref, { "$ref": options[:refmap][ref] })
  end
end

def processSecurity(securityObject)
  securityObject.each do |s|
    securityObject[s].each do |k|
      sname = common.sanitise(k)
      if k != sname
        securityObject[s][sname] = securityObject[s][k]
        securityObject[s].delete k
      end
    end
  end
end

def processSecurityScheme(scheme, options)
  if scheme[:type] == 'basic'
    scheme[:type] = 'http'
    scheme[:scheme] = 'basic'
  end

  if scheme[:type] == 'oauth2'
    flow = {}
    flowName = scheme[:flow]
    if scheme[:flow] == 'application'
      flowName = 'clientCredentials'
    end
    if scheme[:flow] == 'accessCode'
      flowName = 'authorizationCode'
    end
    if scheme[:authorizationUrl]
      flow[:authorizationUrl] = scheme[:authorizationUrl].split('?')[0].strip || '/'
    end
    if scheme[:tokenUrl].is_a?(String)
      flow[:tokenUrl] = scheme[:tokenUrl].split('?')[0].strip || '/'
    end

    flow[:scopes] ||= {}
    scheme[:flows] = {}
    scheme[:flows][flowName] = flow
    scheme.delete :flow
    scheme.delete :authorizationUrl
    scheme.delete :tokenUrl
    scheme.delete :scopes
    if scheme[:name]
      scheme.delete :name
    end
  end
end

def keepParameters(value)
  value && !value["x-s2o-delete"]
end

def processHeader(header, options)
  if header[:'$ref']
    header[:'$ref'] = header[:'$ref'].sub('#/responses/', '#/components/responses/')
  else
    if header[:type] && !header[:schema]
      header[:schema] = {}
    end

    if header[:type]
      header[:schema][:type] = header[:type]
    end
    if header[:items] && !header[:items].is_a(Array)
      if header[:items]:[:collectionFormat] != header[:collectionFormat]
        throwOrWarn('Nested collectionFormats are not supported', header, options)
      end
      header[:items].delete :collectionFormat
    end

    if header[:type] == 'array'
      if header[:collectionFormat] == 'ssv'
        throwOrWarn('collectionFormat:ssv is no longer supported for headers', header, options); ## not lossless
      elsif header[:collectionFormat] == 'pipes'
        throwOrWarn('collectionFormat:pipes is no longer supported for headers', header, options); ## not lossless
      elsif header[:collectionFormat] == 'multi'
        header[:explode] = true
      elsif header[:collectionFormat] == 'tsv'
        throwOrWarn('collectionFormat:tsv is no longer supported', header, options); ## not lossless
        header[:"x-collectionFormat"] = 'tsv'
      else ## 'csv'
        header[:style] = 'simple'
      end

      header.delete :collectionFormat
    elsif header[:collectionFormat]
      options[:patches]+=1
      header.delete :collectionFormat
    end

    header.delete :type
    common[:parameterTypeProperties].each do |pro|
      if header[prop]
        header[:schema][prop] = header[prop]
        header.delete prop
      end
    end

    common[:arrayProperties].each do |prop|
      if header[prop]
        header[:schema][prop] = header[prop]
        header.delete prop
      end
    end
  end
end

def fixParamRef(param, options)
  if param[:'$ref'].index('#/parameters/') >= 0
    refComponents = param[:'$ref'].split('#/parameters/')
    param[:'$ref'] = refComponents[0] + '#/components/parameters/' + common.sanitise(refComponents[1])
  end

  if param[:'$ref'].index('#/definitions/') >= 0
    raise 'Definition used as parameter'
  end
end

def attachRequestBody(op, options)
  newOp = {}
  op.each_keys do |key|
    newOp[key] = op[key]
    if key == 'parameters'
      newOp[:requestBody] = {}
      if options[:rbname]
        newOp[options[:rbname]] = ''
      end
    end
  end

  newOp[:requestBody] = {} ## just in case there are no parameters

  newOp
end

# @returns op, as it may have changed
#
def processParameter(param, op, path, method, index, openapi, options)
  result = {}
  singularRequestBody = true
  originalType = nil

  if op && op[:consumes].is_a?(String)
    op[:consumes] = [op[:consumes]]
  end

  if !openapi[:consumes].is_a?(Array)
    openapi.delete :consumes
  end

  consumes = ((op ? op[:consumes] : nil) || (openapi[:consumes] || [])).find_all(common[:uniqueOnly]);

  if param && param[:'$ref'].is_a?(String)
    ## if we still have a ref here, it must be an internal one
    fixParamRef(param, options);
    ptr = URI.decode_www_form_component(param[:'$ref'].sub('#/components/parameters/', ''))
    rbody = false
    target = openapi[:components][:parameters][ptr]; ## resolves a $ref, must have been sanitised already

    if (!target || target[:"x-s2o-delete"]) &&
       param[:'$ref'].start_with?('#/')
      ## if it's gone, chances are it's a requestBody component now unless spec was broken
      param[:"x-s2o-delete"] = true
      rbody = true
    end

    ## shared formData parameters from swagger or path level could be used in any combination.
    ## we dereference all op.requestBody's then hash them and pull out common ones later

    if rbody
      ref = param[:'$ref']
      newParam = resolveInternal(openapi, param[:'$ref'];
      if !newParam && ref.startsWith('#/')
        throwOrWarn('Could not resolve reference ' + ref, param, options);
      else
        if (newParam)
          param = newParam; ## preserve reference
        end
      end
    end
  end

  if (param && (param.name || param.in))  ## if it's a real parameter OR we've dereferenced it

    if (typeof param['x-deprecated'] === 'boolean')
      param.deprecated = param['x-deprecated'];
      delete param['x-deprecated'];
    end

    if (typeof param['x-example'] !== 'undefined')
      param.example = param['x-example'];
      delete param['x-example'];
    end

    if ((param.in !== 'body') && (!param.type))
      if (options.patch)
        options.patches+=1
        param.type = 'string';
      else
        throwError('(Patchable) parameter.type is mandatory for non-body parameters', options);
      end
    end

    if (param.type && typeof param.type === 'object' && param.type.$ref)
      ## $ref anywhere sensibility
      param.type = resolveInternal(openapi, param.type.$ref)
    end

    if (param.type === 'file')
      param['x-s2o-originalType'] = param.type;
      originalType = param.type;
    end

    if (param.description && typeof param.description === 'object' && param.description.$ref)
      ## $ref anywhere sensibility
      param.description = resolveInternal(openapi, param.description.$ref);
    end

    if (param.description === null)
      delete param.description;
    end

    oldCollectionFormat = param.collectionFormat;
    if ((param.type === 'array') && !oldCollectionFormat)
      oldCollectionFormat = 'csv';
    end
    if (oldCollectionFormat)
      if (param.type !== 'array')
        if (options.patch)
          options.patches+=1
          delete param.collectionFormat;
        else
          throwError('(Patchable) collectionFormat is only applicable to param.type array', options);
        end
      end

      if ((oldCollectionFormat === 'csv') && ((param.in === 'query') || (param.in === 'cookie')))
        param.style = 'form';
        param.explode = false;
      end

      if ((oldCollectionFormat === 'csv') && ((param.in === 'path') || (param.in === 'header')))
        param.style = 'simple';
      end

      if (oldCollectionFormat === 'ssv')
        if (param.in === 'query')
          param.style = 'spaceDelimited';
        else
          throwOrWarn('collectionFormat:ssv is no longer supported except for in:query parameters', param, options); ## not lossless
        end
      end

      if (oldCollectionFormat === 'pipes')
        if (param.in === 'query')
          param.style = 'pipeDelimited';
        else
          throwOrWarn('collectionFormat:pipes is no longer supported except for in:query parameters', param, options); ## not lossless
        end
      end

      if (oldCollectionFormat === 'multi')
        param.explode = true;
      end

      if (oldCollectionFormat === 'tsv')
        throwOrWarn('collectionFormat:tsv is no longer supported', param, options); ## not lossless
        param["x-collectionFormat"] = 'tsv';
      end

      delete param.collectionFormat;
    end

    if (param.type && (param.type !== 'body') && (param.in !== 'formData'))
      if (param.items && param.schema)
        throwOrWarn('parameter has array,items and schema', param, options);
      else
        if (param.schema)
          options.patches++; // already present
        end

        if ((!param.schema) || (typeof param.schema !== 'object'))
          param.schema = {};
        end

        param.schema.type = param.type;
        if (param.items)
          param.schema.items = param.items;
          delete param.items;
          recurse(param.schema.items, null) do |obj, key, state|
            if ((key === 'collectionFormat') && (typeof obj[key] === 'string'))
              if (oldCollectionFormat && obj[key] !== oldCollectionFormat)
                throwOrWarn('Nested collectionFormats are not supported', param, options);
              end
              delete obj[key]; // not lossless
            end
            ## items in 2.0 was a subset of the JSON-Schema items
            ## object, it gets fixed up below
          end
        end
        for (let prop of common.parameterTypeProperties)
          if typeof param[prop] !== 'undefined'
            param.schema[prop] = param[prop];
          end
          delete param[prop];
        end
      end
    end

    if (param.schema)
      fixUpSchema(param.schema,options);
    end

    if (param["x-ms-skip-url-encoding"])
      if (param.in === 'query') ## might be in:path, not allowed in OAS3
        param.allowReserved = true;
        delete param["x-ms-skip-url-encoding"];
      end
    end
  end


  if (param && param.in === 'formData')
    ## convert to requestBody component
    singularRequestBody = false;
    result.content = {};
    let contentType = 'application/x-www-form-urlencoded';
    if ((consumes.length) && (consumes.indexOf('multipart/form-data') >= 0))
      contentType = 'multipart/form-data';
    end

    result.content[contentType] = {};
    if (param.schema)
      result.content[contentType].schema = param.schema;
      if (param.schema.$ref)
        result['x-s2o-name'] = decodeURIComponent(param.schema.$ref.replace('#/components/schemas/', ''));
      end
    else
      result.content[contentType].schema = {};
      result.content[contentType].schema.type = 'object';
      result.content[contentType].schema.properties = {};
      result.content[contentType].schema.properties[param.name] = {};
      let schema = result.content[contentType].schema;
      let target = result.content[contentType].schema.properties[param.name];
      if (param.description)
        target.description = param.description;
      end
      if (param.example)
        target.example = param.example;
      end
      if (param.type)
        target.type = param.type;
      end

      for (let prop of common.parameterTypeProperties)
        if (typeof param[prop] !== 'undefined')
          target[prop] = param[prop];
        end
      end

      if (param.required === true)
        if (!schema.required)
          schema.required = [];
        end
        schema.required.push(param.name);
        result.required = true;
      end
      if (typeof param.default !== 'undefined')
        target.default = param.default;
      end
      if (target.properties)
        target.properties = param.properties;
      end
      if (param.allOf)
        target.allOf = param.allOf; ## new are anyOf, oneOf, not
      end
      if ((param.type === 'array') && (param.items))
        target.items = param.items;
        if (target.items.collectionFormat)
          delete target.items.collectionFormat;
        end
      end
      if ((originalType === 'file') || (param['x-s2o-originalType'] === 'file'))
        target.type = 'string';
        target.format = 'binary';
      end

      ## Copy any extensions on the form param to the target schema property.
      copyExtensions(param, target);
    end
  elsif (param && (param.type === 'file'))
    ## convert to requestBody
    if (param.required)
      result.required = param.required;
    end
    result.content = {};
    result.content["application/octet-stream"] = {};
    result.content["application/octet-stream"].schema = {};
    result.content["application/octet-stream"].schema.type = 'string';
    result.content["application/octet-stream"].schema.format = 'binary';
    copyExtensions(param, result);
  end

  if (param && param.in === 'body')
    result.content = {};
    if (param.name)
      result['x-s2o-name'] = (op && op.operationId ? common.sanitiseAll(op.operationId) : '') + ('_' + param.name).toCamelCase();
    end

    if (param.description)
      result.description = param.description;
    end
    if (param.required)
      result.required = param.required;
    end

    ## Set the "request body name" extension on the operation if requested.
    if (op && options.rbname && param.name)
      op[options.rbname] = param.name;
    end

    if (param.schema && param.schema.$ref)
      result['x-s2o-name'] = decodeURIComponent(param.schema.$ref.replace('#/components/schemas/', ''));
    elsif (param.schema && (param.schema.type === 'array') && param.schema.items && param.schema.items.$ref)
      result['x-s2o-name'] = decodeURIComponent(param.schema.items.$ref.replace('#/components/schemas/', '')) + 'Array';
    end

    if (!consumes.length)
      consumes.push('application/json'); // TODO verify default
    end

    for (let mimetype of consumes)
      result.content[mimetype] = {};
      result.content[mimetype].schema = clone(param.schema || {});
      fixUpSchema(result.content[mimetype].schema,options);
    end

    ## Copy any extensions from the original parameter to the new requestBody
    copyExtensions(param, result);
  end

  if (Object.keys(result).length > 0)
    param["x-s2o-delete"] = true;
    ## work out where to attach the requestBody
    if (op)
      if (op.requestBody && singularRequestBody)
        op.requestBody["x-s2o-overloaded"] = true;
        let opId = op.operationId || index;

        throwOrWarn('Operation ' + opId + ' has multiple requestBodies', op, options);
      else
        if (!op.requestBody)
          op = path[method] = attachRequestBody(op,options); ## make sure we have one
        end

        if ((op.requestBody.content && op.requestBody.content["multipart/form-data"])
            && (op.requestBody.content["multipart/form-data"].schema)
            && (op.requestBody.content["multipart/form-data"].schema.properties)
            && (result.content["multipart/form-data"])
            && (result.content["multipart/form-data"].schema)
            && (result.content["multipart/form-data"].schema.properties))
          op.requestBody.content["multipart/form-data"].schema.properties =
            Object.assign(op.requestBody.content["multipart/form-data"].schema.properties, result.content["multipart/form-data"].schema.properties);
          op.requestBody.content["multipart/form-data"].schema.required =
            (op.requestBody.content["multipart/form-data"].schema.required || []).
              concat(result.content["multipart/form-data"].schema.required||[]);
          if (!op.requestBody.content["multipart/form-data"].schema.required.length)
            delete op.requestBody.content["multipart/form-data"].schema.required;
          end
        elsif (op.requestBody.content &&
               op.requestBody.content["application/x-www-form-urlencoded"] &&
               op.requestBody.content["application/x-www-form-urlencoded"].schema &&
               op.requestBody.content["application/x-www-form-urlencoded"].schema.properties) &&
              result.content["application/x-www-form-urlencoded"] &&
              result.content["application/x-www-form-urlencoded"].schema &&
              result.content["application/x-www-form-urlencoded"].schema.properties
          op.requestBody.content["application/x-www-form-urlencoded"].schema.properties =
            Object.assign(
              op.requestBody.content["application/x-www-form-urlencoded"].schema.properties,
              result.content["application/x-www-form-urlencoded"].schema.properties
            )
          op.requestBody.content["application/x-www-form-urlencoded"].schema.required =
            (op.requestBody.content["application/x-www-form-urlencoded"].schema.required || []).
              concat(result.content["application/x-www-form-urlencoded"].schema.required||[])
          if !op.requestBody.content["application/x-www-form-urlencoded"].schema.required.length
            delete op.requestBody.content["application/x-www-form-urlencoded"].schema.required;
          end
        else
          op.requestBody = Object.assign(op.requestBody, result);
          if (!op.requestBody['x-s2o-name'])
            if (op.requestBody.schema && op.requestBody.schema.$ref)
              op.requestBody['x-s2o-name'] =
                decodeURIComponent(op.requestBody.schema.$ref.replace('#/components/schemas/', '')).split('/').join('');
            elsif (op.operationId)
              op.requestBody['x-s2o-name'] = common.sanitiseAll(op.operationId);
            end
          end
        end
      end
    end
  end

  ## tidy up
  if (param && !param['x-s2o-delete'])
    delete param.type;
    for (let prop of common.parameterTypeProperties)
      delete param[prop];
    end

    if (param.in === 'path') && ((typeof param.required === 'undefined') || (param.required !== true))
      if (options.patch)
        options.patches+=1
        param.required = true;
      else
        throwError('(Patchable) path parameters must be required:true ['+param.name+' in '+index+']', options);
      end
    end
  end

  op;
end



def extract_server_parameters(server)
  if !server || !server[:url] || !server[:url].is_a?(String)
    return server
  end

  server[:url] = server[:url].split('{{').join('{')
  server[:url] = server[:url].split('}}').join('}')
  server[:url].gsub(/\{(.+?)\}/) do |_matched| ## TODO extend to :parameters (not port)?
    server[:variables] ||= {}
    server[:variables][$1] = { default: 'unknown' }
  end

  server
end

def fix_info(openapi, exception: false)
  if !openapi[:info]
    if exception
      raise S2OError, '(Patchable) info object is mandatory'
    else
      openapi[:info] = { version: '', title: '' }
    end
  end
  if !openapi[:info].is_a?(Hash)
    raise S2OError, 'info must be an Hash'
  end

  if !openapi[:info][:title]
    if exception
      raise S2OError, '(Patchable) info[title] cannot be null'
    else
      openapi[:info][:title] = ''
    end
  end

  if !openapi[:info][:version]
    if exception
      raise S2OError, '(Patchable) info[version] cannot be null'
    else
      openapi[:info][:version] = ''
    end
  end

  if !openapi[:info][:version].is_a?(String)
    if exception
      raise S2OError, '(Patchable) info[version] must be a string'
    else
      openapi[:info][:version] = openapi[:info][:version].to_s
    end
  end

  if !openapi[:info][:logo]
    if exception
      raise S2OError, '(Patchable) info should not have logo property'
    else
      openapi[:info][:"x-logo"] = openapi[:info][:logo]
      openapi[:info].delete(:logo)
    end
  end

  if !openapi[:info][:termsOfService]
    if exception
      raise S2OError, '(Patchable) info[termsOfService] cannot be null'
    else
      openapi[:info][:termsOfService:] = ''
    end
  end

  begin
    _url = URI.parse(openapi[:info][:termsOfService])
  rescue => URI::Error => _ex
    if exception
      raise S2OError, '(Patchable) info.termsOfService must be a URL'
    else
      openapi[:info].delete(:termsOfService)
    end
  end
end

def fix_paths(openapi, exception: false)
  if !openapi[:paths]
    if exception
      raise S2OError, '(Patchable) paths object is mandatory'
    else
      openapi[:paths] = {}
    end
  end
end


def detect_object_references(obj, anchors:)
  seen = Set.new
  key_path = Set.new

  obj.each_pair do |key, val|
    key_path << key
    if val.is_a?(Hash)
      if seen.member?(val)
        if anchors
          obj[key] = JSON.parse(JSON.dump(val))
        else
          raise "YAML anchor or merge key at #{key_path.join('/')}"
        end
      else
        seen << val
      end
    end
  end
end


def convert_obj(swagger, anchors: true, **options)

  @original = swagger;
  @text = YAML.parse(swagger)

  @externals = []
  @externalRefs = {}
  @rewriteRefs = true ## avoids stack explosions
  @preserveMiro = true
  @patches = 0

  cache = {}

  if @source
    cache[@source] = @original
  end

  detectObjectReferences(swagger, anchors: anchors);

  if swagger[:openapi] && swagger[:openapi].is_a?(String) && swagger[:openapi].starts_with?('3.')
    openapi = circular_clone(swagger)
    fix_info(openapi, exception: exception)
    fix_paths(openapi, exception: exception)

    if swagger[:swagger] != "2.0"
      raise S2OError, "Unsupported swagger/OpenAPI version: #{swagger[:openapi] ? swagger[:openapi] : swagger[:swagger]}"
    end

    openapi = options[:openapi] = {}
    openapi[:openapi] = (options[:targetVersion].is_a?(String) && options[:targetVersion].start_with?('3.')) ? options[:targetVersion] : targetVersion ## semver

    if options[:origin]
      openapi[:"x-origin"] ||= []
    end

    origin = {}
    origin[:url] = options[:source] || options[:origin]
    origin[:format] = 'swagger'
    origin.version = swagger[:swagger]
    origin.converter = {}
    origin.converter[:url] = 'https://github.com/mermade/oas-kit'
    origin.converter[:version] = ourVersion
    openapi[:"x-origin"].push(origin)
  end

  ## we want the new and existing properties to appear in a sensible order. Not guaranteed
  openapi.merge!(circular_clone(swagger))
  openapi.delete :swagger
  openapi.each_pair do |key, val|
    if val.nil? && (!key.start_with?('x-')) && key != 'default' && (state.path.indexOf('/example') < 0)
      obj.delete key ## this saves *so* much grief later
    end
  end

  if swagger[:host]
    (swagger[:schemes].is_a?(Array) ? swagger[:schemes] : ['']).each do |s|

      server = {}
      basePath = (swagger[:basePath] || '').sub(/\/$/, '') ## Trailing slashes generally shouldn't be included
      server[:url] = (s ? "#{s}:" : '') + '//' + swagger[:host] + basePath
      extract_server_parameters(server)
      openapi[:servers] ||= []

      openapi[:servers].push(server)
    end
  elsif swagger[:basePath]
    server = {}
    server[:url] = swagger[:basePath]
    extract_server_parameters(server)
    openapi[:servers] ||= []
    openapi[:servers].push(server)
  end

  openapi.delete host
  openapi.delete basePath

  if openapi[:'x-servers'] && openapi[:'x-servers'].is_a?(Array)
    openapi[:servers] = openapi[:'x-servers']
    openapi.delete :'x-servers'
  end

  ## TODO APIMatic extensions (x-server-configuration) ?

  if swagger[:'x-ms-parameterized-host']
    xMsPHost = swagger[:'x-ms-parameterized-host']
    server = {}
    server[:url] = xMsPHost[:hostTemplate] + (swagger[:basePath] ? swagger[:basePath] : '')
    server[:variables] = {}
    paramNames = server[:url].match(/\{\w+\}/g)
    xMsPHost[:parameters].each do |s|
      param = xMsPHost[:parameters][msp]
      if param.$ref
        param = clone(resolveInternal(openapi, param.$ref))
      end
      if !msp.start_with('x-')
        param.delete :required ## all true
        param.delete :type ## all strings
        param.delete :in ## all 'host'
        if !param[:default]
          if param[:enum]
            param[:default] = param[:enum][0]
          else
            param[:default] = 'none'
          end
        end

        if !param[:name]
          param[:name] = paramNames[msp].gsub('{','').gsub('}','')
        end
        server[:variables][param[:name]] = param
        param.delete :name
      end
    end

    openapi[:servers] ||= []
    if xMsPHost[:useSchemePrefix] == false
      ## The server URL already includes a protocol scheme
      openapi[:servers].push(server)
    else
      ## Define this server once for each given protocol scheme
      swagger[:schemes].each do |scheme|
        obj = server.dup
        obj[:url] = scheme + '://' + server[:url]
        openapi[:servers].push(obj)
      end
    end
    openapi.delete :'x-ms-parameterized-host'
  end

  fix_info(openapi, exception: exception)
  fix_paths(openapi, exception: exception)

  if openapi[:consumes].is_a?(String)
    openapi[:consumes] = [openapi[:consumes]]
  end

  if openapi[:produces].is_a?(String)
    openapi[:produces] = [openapi[:produces]]
  end

  openapi[:components] = {}
  if openapi[:'x-callbacks']
    openapi[:components].callbacks = openapi[:'x-callbacks']
    openapi.delete :'x-callbacks'
  end
  openapi[:components][:examples] = {}
  openapi[:components][:headers] = {}
  if openapi[:'x-links']
    openapi[:components][:links] = openapi[:'x-links']
    openapi.delete :'x-links'
  end

  openapi[:components][:parameters] = openapi[:parameters] || {}
  openapi[:components][:responses] = openapi[:responses] || {}
  openapi[:components][:requestBodies] = {}
  openapi[:components][:securitySchemes] = openapi[:securityDefinitions] || {}
  openapi[:components][:schemas] = openapi[:definitions] || {}
  openapi.delete :definitions
  openapi.delete :responses
  openapi.delete :parameters
  openapi.delete :securityDefinitions
end

