package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.annotation.JacksonStdImpl;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.deser.NullValueProvider;
import com.fasterxml.jackson.databind.deser.ValueInstantiator;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.type.LogicalType;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;

@JacksonStdImpl
/* loaded from: classes.dex */
public final class StringCollectionDeserializer extends ContainerDeserializerBase<Collection<String>> implements ContextualDeserializer {
    protected final JsonDeserializer<Object> _delegateDeserializer;
    protected final JsonDeserializer<String> _valueDeserializer;
    protected final ValueInstantiator _valueInstantiator;

    public StringCollectionDeserializer(JavaType javaType, JsonDeserializer<?> jsonDeserializer, ValueInstantiator valueInstantiator) {
        this(javaType, valueInstantiator, null, jsonDeserializer, jsonDeserializer, null);
    }

    private static Collection<String> castToCollection(Object obj) {
        if (obj != null) {
            if (obj.getClass() == ArrayList.class) {
                return (ArrayList) obj;
            }
            if (obj.getClass() == HashSet.class) {
                return (HashSet) obj;
            }
        }
        return (Collection) obj;
    }

    private Collection<String> deserializeUsingCustom(JsonParser jsonParser, DeserializationContext deserializationContext, Collection<String> collection, JsonDeserializer<String> jsonDeserializer) throws IOException {
        String strDeserialize;
        while (true) {
            try {
                if (jsonParser.nextTextValue() == null) {
                    JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
                    if (jsonTokenCurrentToken == JsonToken.END_ARRAY) {
                        return collection;
                    }
                    if (jsonTokenCurrentToken != JsonToken.VALUE_NULL) {
                        strDeserialize = jsonDeserializer.deserialize(jsonParser, deserializationContext);
                    } else if (!this._skipNullValues) {
                        strDeserialize = (String) this._nullProvider.getNullValue(deserializationContext);
                    }
                } else {
                    strDeserialize = jsonDeserializer.deserialize(jsonParser, deserializationContext);
                }
                collection.add(strDeserialize);
            } catch (Exception e) {
                throw JsonMappingException.wrapWithPath(e, collection, collection.size());
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00aa A[Catch: Exception -> 0x00b1, TRY_ENTER, TryCatch #0 {Exception -> 0x00b1, blocks: (B:37:0x00aa, B:40:0x00b4), top: B:46:0x00a8 }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00b4 A[Catch: Exception -> 0x00b1, TRY_LEAVE, TryCatch #0 {Exception -> 0x00b1, blocks: (B:37:0x00aa, B:40:0x00b4), top: B:46:0x00a8 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.util.Collection<java.lang.String> handleNonArray(com.fasterxml.jackson.core.JsonParser r11, com.fasterxml.jackson.databind.DeserializationContext r12, java.util.Collection<java.lang.String> r13) throws java.io.IOException {
        /*
            r10 = this;
            java.lang.Boolean r0 = r10._unwrapSingle
            java.lang.Boolean r1 = java.lang.Boolean.TRUE
            if (r0 == r1) goto L2b
            if (r0 != 0) goto L11
            com.fasterxml.jackson.databind.DeserializationFeature r0 = com.fasterxml.jackson.databind.DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY
            boolean r0 = r12.isEnabled(r0)
            if (r0 == 0) goto L11
            goto L2b
        L11:
            com.fasterxml.jackson.core.JsonToken r13 = com.fasterxml.jackson.core.JsonToken.VALUE_STRING
            boolean r13 = r11.hasToken(r13)
            if (r13 == 0) goto L20
            java.lang.Object r11 = r10._deserializeFromString(r11, r12)
            java.util.Collection r11 = (java.util.Collection) r11
            return r11
        L20:
            com.fasterxml.jackson.databind.JavaType r13 = r10._containerType
            java.lang.Object r11 = r12.handleUnexpectedToken(r13, r11)
            java.util.Collection r11 = castToCollection(r11)
            return r11
        L2b:
            com.fasterxml.jackson.databind.JsonDeserializer<java.lang.String> r0 = r10._valueDeserializer
            com.fasterxml.jackson.core.JsonToken r1 = r11.currentToken()
            com.fasterxml.jackson.core.JsonToken r2 = com.fasterxml.jackson.core.JsonToken.VALUE_NULL
            if (r1 != r2) goto L45
            boolean r11 = r10._skipNullValues
            if (r11 == 0) goto L3a
            return r13
        L3a:
            com.fasterxml.jackson.databind.deser.NullValueProvider r11 = r10._nullProvider
            java.lang.Object r11 = r11.getNullValue(r12)
            java.lang.String r11 = (java.lang.String) r11
            r1 = r10
            goto Lba
        L45:
            com.fasterxml.jackson.core.JsonToken r1 = com.fasterxml.jackson.core.JsonToken.VALUE_STRING
            boolean r1 = r11.hasToken(r1)
            if (r1 == 0) goto L7b
            java.lang.String r1 = r11.getText()
            boolean r2 = r1.isEmpty()
            if (r2 == 0) goto L7f
            com.fasterxml.jackson.databind.type.LogicalType r1 = r10.logicalType()
            java.lang.Class r2 = r10.handledType()
            com.fasterxml.jackson.databind.cfg.CoercionInputShape r3 = com.fasterxml.jackson.databind.cfg.CoercionInputShape.EmptyString
            com.fasterxml.jackson.databind.cfg.CoercionAction r7 = r12.findCoercionAction(r1, r2, r3)
            com.fasterxml.jackson.databind.cfg.CoercionAction r1 = com.fasterxml.jackson.databind.cfg.CoercionAction.Fail
            if (r7 == r1) goto L7b
            java.lang.Class r8 = r10.handledType()
            java.lang.String r9 = "empty String (\"\")"
            r4 = r10
            r5 = r11
            r6 = r12
            java.lang.Object r11 = r4._deserializeFromEmptyString(r5, r6, r7, r8, r9)
            java.util.Collection r11 = castToCollection(r11)
            return r11
        L7b:
            r1 = r10
            r2 = r11
            r3 = r12
            goto La8
        L7f:
            r2 = r11
            r3 = r12
            boolean r11 = com.fasterxml.jackson.databind.deser.std.StdDeserializer._isBlank(r1)
            if (r11 == 0) goto La7
            com.fasterxml.jackson.databind.type.LogicalType r11 = r10.logicalType()
            java.lang.Class r12 = r10.handledType()
            com.fasterxml.jackson.databind.cfg.CoercionAction r1 = com.fasterxml.jackson.databind.cfg.CoercionAction.Fail
            com.fasterxml.jackson.databind.cfg.CoercionAction r4 = r3.findCoercionFromBlankString(r11, r12, r1)
            if (r4 == r1) goto La7
            java.lang.Class r5 = r10.handledType()
            java.lang.String r6 = "blank String (all whitespace)"
            r1 = r10
            java.lang.Object r11 = r1._deserializeFromEmptyString(r2, r3, r4, r5, r6)
            java.util.Collection r11 = castToCollection(r11)
            return r11
        La7:
            r1 = r10
        La8:
            if (r0 != 0) goto Lb4
            com.fasterxml.jackson.databind.deser.NullValueProvider r11 = r1._nullProvider     // Catch: java.lang.Exception -> Lb1
            java.lang.String r11 = r10._parseString(r2, r3, r11)     // Catch: java.lang.Exception -> Lb1
            goto Lba
        Lb1:
            r0 = move-exception
            r11 = r0
            goto Lbe
        Lb4:
            java.lang.Object r11 = r0.deserialize(r2, r3)     // Catch: java.lang.Exception -> Lb1
            java.lang.String r11 = (java.lang.String) r11     // Catch: java.lang.Exception -> Lb1
        Lba:
            r13.add(r11)
            return r13
        Lbe:
            int r12 = r13.size()
            com.fasterxml.jackson.databind.JsonMappingException r11 = com.fasterxml.jackson.databind.JsonMappingException.wrapWithPath(r11, r13, r12)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.std.StringCollectionDeserializer.handleNonArray(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext, java.util.Collection):java.util.Collection");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0031  */
    @Override // com.fasterxml.jackson.databind.deser.ContextualDeserializer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.fasterxml.jackson.databind.JsonDeserializer<?> createContextual(com.fasterxml.jackson.databind.DeserializationContext r6, com.fasterxml.jackson.databind.BeanProperty r7) throws com.fasterxml.jackson.databind.JsonMappingException {
        /*
            r5 = this;
            com.fasterxml.jackson.databind.deser.ValueInstantiator r0 = r5._valueInstantiator
            r1 = 0
            if (r0 == 0) goto L31
            com.fasterxml.jackson.databind.introspect.AnnotatedWithParams r0 = r0.getArrayDelegateCreator()
            if (r0 == 0) goto L1a
            com.fasterxml.jackson.databind.deser.ValueInstantiator r0 = r5._valueInstantiator
            com.fasterxml.jackson.databind.DeserializationConfig r2 = r6.getConfig()
            com.fasterxml.jackson.databind.JavaType r0 = r0.getArrayDelegateType(r2)
            com.fasterxml.jackson.databind.JsonDeserializer r0 = r5.findDeserializer(r6, r0, r7)
            goto L32
        L1a:
            com.fasterxml.jackson.databind.deser.ValueInstantiator r0 = r5._valueInstantiator
            com.fasterxml.jackson.databind.introspect.AnnotatedWithParams r0 = r0.getDelegateCreator()
            if (r0 == 0) goto L31
            com.fasterxml.jackson.databind.deser.ValueInstantiator r0 = r5._valueInstantiator
            com.fasterxml.jackson.databind.DeserializationConfig r2 = r6.getConfig()
            com.fasterxml.jackson.databind.JavaType r0 = r0.getDelegateType(r2)
            com.fasterxml.jackson.databind.JsonDeserializer r0 = r5.findDeserializer(r6, r0, r7)
            goto L32
        L31:
            r0 = r1
        L32:
            com.fasterxml.jackson.databind.JsonDeserializer<java.lang.String> r2 = r5._valueDeserializer
            com.fasterxml.jackson.databind.JavaType r3 = r5._containerType
            com.fasterxml.jackson.databind.JavaType r3 = r3.getContentType()
            if (r2 != 0) goto L47
            com.fasterxml.jackson.databind.JsonDeserializer r2 = r5.findConvertingContentDeserializer(r6, r7, r2)
            if (r2 != 0) goto L4b
            com.fasterxml.jackson.databind.JsonDeserializer r2 = r6.findContextualValueDeserializer(r3, r7)
            goto L4b
        L47:
            com.fasterxml.jackson.databind.JsonDeserializer r2 = r6.handleSecondaryContextualization(r2, r7, r3)
        L4b:
            java.lang.Class<java.util.Collection> r3 = java.util.Collection.class
            com.fasterxml.jackson.annotation.JsonFormat$Feature r4 = com.fasterxml.jackson.annotation.JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY
            java.lang.Boolean r3 = r5.findFormatFeature(r6, r7, r3, r4)
            com.fasterxml.jackson.databind.deser.NullValueProvider r6 = r5.findContentNullProvider(r6, r7, r2)
            boolean r7 = r5.isDefaultDeserializer(r2)
            if (r7 == 0) goto L5e
            goto L5f
        L5e:
            r1 = r2
        L5f:
            com.fasterxml.jackson.databind.deser.std.StringCollectionDeserializer r6 = r5.withResolved(r0, r1, r6, r3)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.std.StringCollectionDeserializer.createContextual(com.fasterxml.jackson.databind.DeserializationContext, com.fasterxml.jackson.databind.BeanProperty):com.fasterxml.jackson.databind.JsonDeserializer");
    }

    @Override // com.fasterxml.jackson.databind.deser.std.StdDeserializer, com.fasterxml.jackson.databind.JsonDeserializer
    public Object deserializeWithType(JsonParser jsonParser, DeserializationContext deserializationContext, TypeDeserializer typeDeserializer) throws IOException {
        return typeDeserializer.deserializeTypedFromArray(jsonParser, deserializationContext);
    }

    @Override // com.fasterxml.jackson.databind.deser.std.ContainerDeserializerBase
    public JsonDeserializer<Object> getContentDeserializer() {
        return this._valueDeserializer;
    }

    @Override // com.fasterxml.jackson.databind.deser.std.StdDeserializer
    public ValueInstantiator getValueInstantiator() {
        return this._valueInstantiator;
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public boolean isCachable() {
        return this._valueDeserializer == null && this._delegateDeserializer == null;
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public LogicalType logicalType() {
        return LogicalType.Collection;
    }

    public StringCollectionDeserializer withResolved(JsonDeserializer<?> jsonDeserializer, JsonDeserializer<?> jsonDeserializer2, NullValueProvider nullValueProvider, Boolean bool) {
        return (Objects.equals(this._unwrapSingle, bool) && this._nullProvider == nullValueProvider && this._valueDeserializer == jsonDeserializer2 && this._delegateDeserializer == jsonDeserializer) ? this : new StringCollectionDeserializer(this._containerType, this._valueInstantiator, jsonDeserializer, jsonDeserializer2, nullValueProvider, bool);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public StringCollectionDeserializer(JavaType javaType, ValueInstantiator valueInstantiator, JsonDeserializer<?> jsonDeserializer, JsonDeserializer<?> jsonDeserializer2, NullValueProvider nullValueProvider, Boolean bool) {
        super(javaType, nullValueProvider, bool);
        this._valueDeserializer = jsonDeserializer2;
        this._valueInstantiator = valueInstantiator;
        this._delegateDeserializer = jsonDeserializer;
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public Collection<String> deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        JsonDeserializer<Object> jsonDeserializer = this._delegateDeserializer;
        if (jsonDeserializer != null) {
            return castToCollection(this._valueInstantiator.createUsingDelegate(deserializationContext, jsonDeserializer.deserialize(jsonParser, deserializationContext)));
        }
        return deserialize(jsonParser, deserializationContext, castToCollection(this._valueInstantiator.createUsingDefault(deserializationContext)));
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public Collection<String> deserialize(JsonParser jsonParser, DeserializationContext deserializationContext, Collection<String> collection) throws IOException {
        String str_parseString;
        if (!jsonParser.isExpectedStartArrayToken()) {
            return handleNonArray(jsonParser, deserializationContext, collection);
        }
        JsonDeserializer<String> jsonDeserializer = this._valueDeserializer;
        if (jsonDeserializer != null) {
            return deserializeUsingCustom(jsonParser, deserializationContext, collection, jsonDeserializer);
        }
        while (true) {
            try {
                String strNextTextValue = jsonParser.nextTextValue();
                if (strNextTextValue != null) {
                    collection.add(strNextTextValue);
                } else {
                    JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
                    if (jsonTokenCurrentToken == JsonToken.END_ARRAY) {
                        return collection;
                    }
                    if (jsonTokenCurrentToken == JsonToken.VALUE_NULL) {
                        if (!this._skipNullValues) {
                            str_parseString = (String) this._nullProvider.getNullValue(deserializationContext);
                        }
                    } else {
                        str_parseString = _parseString(jsonParser, deserializationContext, this._nullProvider);
                    }
                    collection.add(str_parseString);
                }
            } catch (Exception e) {
                throw JsonMappingException.wrapWithPath(e, collection, collection.size());
            }
        }
    }
}
