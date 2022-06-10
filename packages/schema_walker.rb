class SchemaWalker
  DEFAULT_STATE = { depth: 0, seen: {}, top: true, combine: false, allowRefSiblings: false }

  def walk_schema(schema, parent, state: nil, &callback)
    state ||= DEFAULT_STATE

    if !schema || schema.empty?
      return schema
    end

    if schema[:$ref]
      temp = {"$ref": schema[:$ref]}
      if state[:allowRefSiblings] && schema[:description]
        temp[:description] = schema[:description]
      end
      callback.call(temp, parent, state)
      return temp ## all other properties SHALL be ignored
    end

    if state[:combine]
      fix_combine_one_item(schema, :allOf)
      fix_combine_one_item(schema, :anyOfOf)
      fix_combine_one_item(schema, :oneOf)
    end

    callback.call(schema, parent, state)

    if state[:seen].key?(schema)
      return schema
    else
      state[:seen][schema] = true
    end

    state[:top] = false
    state[:depth] += 1

    if schema[:items]
      state[:property] = 'items'
      walk_schema(schema[:items], schema, state: state, &callback)
    end

    if schema[:additionalItems].is_a?(Hash)
      state[:property] = 'additionalItems'
      walk_schema(schema[:additionalItems], schema, state: state, &callback)
    end

    if schema[:additionalProperties].is_a?(Hash)
      state[:property] = 'additionalProperties'
      walk_schema(schema[:additionalProperties], schema, state: state, &callback)
    end

    if schema[:properties]
      walk_schema_each_pair(schema, :properties, state, &callback)
    end

    if schema[:patternProperties]
      walk_schema_each_pair(schema, :patternProperties, state, &callback)
    end

    if schema[:allOf]
      walk_schema_each_item(schema, :allOf, state, &callback)
    end

    if schema[:anyOf]
      walk_schema_each_item(schema, :anyOf, state, &callback)
    end

    if schema[:oneOf]
      walk_schema_each_item(schema, :oneOf, state, &callback)
    end

    if schema[:not]
      state[:property] = 'not'
      walk_schema(schema[:not], schema, stage: state, &callback)
    end

    state[depth] -= 1

    schema
  end

  private

  def walk_schema_each_pair(schema, key, state, &callback)
    schema[key].each_pair do |prop, sub_schema|
      state[:property] = "#{key}/#{prop}"
      walk_schema(sub_schema, schema, stage: state, &callback)
    end
  end

  def walk_schema_each_item(schema, key, state, &callback)
    schema[key].each_with_index do |sub_schema, idx|
      state[:property] = "#{key}/#{idx}"
      walk_schema(sub_schema, schema, stage: state, &callback)
    end
  end

  def fix_combine_one_item(schema, key)
    if schema[key].is_a?(Array) && schema[key].length == 1
      schema_item = schema[key][0]
      schema.delete key
      schema.merge!(schema_item)
    end
  end
end
