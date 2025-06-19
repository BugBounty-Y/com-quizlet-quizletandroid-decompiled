package com.fasterxml.jackson.databind.deser.impl;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.jsontype.TypeDeserializer;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public class ExternalTypeHandler {
    private final JavaType _beanType;
    private final Map<String, Object> _nameToPropertyIndex;
    private final ExtTypedProperty[] _properties;
    private final TokenBuffer[] _tokens;
    private final String[] _typeIds;

    public static class Builder {
        private final JavaType _beanType;
        private final List<ExtTypedProperty> _properties = new ArrayList();
        private final Map<String, Object> _nameToPropertyIndex = new HashMap();

        public Builder(JavaType javaType) {
            this._beanType = javaType;
        }

        private void _addPropertyIndex(String str, Integer num) {
            Object obj = this._nameToPropertyIndex.get(str);
            if (obj == null) {
                this._nameToPropertyIndex.put(str, num);
                return;
            }
            if (obj instanceof List) {
                ((List) obj).add(num);
                return;
            }
            LinkedList linkedList = new LinkedList();
            linkedList.add(obj);
            linkedList.add(num);
            this._nameToPropertyIndex.put(str, linkedList);
        }

        public void addExternal(SettableBeanProperty settableBeanProperty, TypeDeserializer typeDeserializer) {
            Integer numValueOf = Integer.valueOf(this._properties.size());
            this._properties.add(new ExtTypedProperty(settableBeanProperty, typeDeserializer));
            _addPropertyIndex(settableBeanProperty.getName(), numValueOf);
            _addPropertyIndex(typeDeserializer.getPropertyName(), numValueOf);
        }

        public ExternalTypeHandler build(BeanPropertyMap beanPropertyMap) {
            int size = this._properties.size();
            ExtTypedProperty[] extTypedPropertyArr = new ExtTypedProperty[size];
            for (int i = 0; i < size; i++) {
                ExtTypedProperty extTypedProperty = this._properties.get(i);
                SettableBeanProperty settableBeanPropertyFind = beanPropertyMap.find(extTypedProperty.getTypePropertyName());
                if (settableBeanPropertyFind != null) {
                    extTypedProperty.linkTypeProperty(settableBeanPropertyFind);
                }
                extTypedPropertyArr[i] = extTypedProperty;
            }
            return new ExternalTypeHandler(this._beanType, extTypedPropertyArr, this._nameToPropertyIndex, null, null);
        }
    }

    public static final class ExtTypedProperty {
        private final SettableBeanProperty _property;
        private final TypeDeserializer _typeDeserializer;
        private SettableBeanProperty _typeProperty;
        private final String _typePropertyName;

        public ExtTypedProperty(SettableBeanProperty settableBeanProperty, TypeDeserializer typeDeserializer) {
            this._property = settableBeanProperty;
            this._typeDeserializer = typeDeserializer;
            this._typePropertyName = typeDeserializer.getPropertyName();
        }

        public String getDefaultTypeId() {
            Class<?> defaultImpl = this._typeDeserializer.getDefaultImpl();
            if (defaultImpl == null) {
                return null;
            }
            return this._typeDeserializer.getTypeIdResolver().idFromValueAndType(null, defaultImpl);
        }

        public SettableBeanProperty getProperty() {
            return this._property;
        }

        public SettableBeanProperty getTypeProperty() {
            return this._typeProperty;
        }

        public String getTypePropertyName() {
            return this._typePropertyName;
        }

        public boolean hasDefaultType() {
            return this._typeDeserializer.hasDefaultImpl();
        }

        public boolean hasTypePropertyName(String str) {
            return str.equals(this._typePropertyName);
        }

        public void linkTypeProperty(SettableBeanProperty settableBeanProperty) {
            this._typeProperty = settableBeanProperty;
        }
    }

    public ExternalTypeHandler(JavaType javaType, ExtTypedProperty[] extTypedPropertyArr, Map<String, Object> map, String[] strArr, TokenBuffer[] tokenBufferArr) {
        this._beanType = javaType;
        this._properties = extTypedPropertyArr;
        this._nameToPropertyIndex = map;
        this._typeIds = strArr;
        this._tokens = tokenBufferArr;
    }

    private final boolean _handleTypePropertyValue(JsonParser jsonParser, DeserializationContext deserializationContext, String str, Object obj, String str2, int i) throws IOException {
        if (!this._properties[i].hasTypePropertyName(str)) {
            return false;
        }
        if (obj == null || this._tokens[i] == null) {
            this._typeIds[i] = str2;
            return true;
        }
        _deserializeAndSet(jsonParser, deserializationContext, obj, i, str2);
        this._tokens[i] = null;
        return true;
    }

    public static Builder builder(JavaType javaType) {
        return new Builder(javaType);
    }

    public final Object _deserialize(JsonParser jsonParser, DeserializationContext deserializationContext, int i, String str) throws IOException {
        JsonParser jsonParserAsParser = this._tokens[i].asParser(jsonParser);
        if (jsonParserAsParser.nextToken() == JsonToken.VALUE_NULL) {
            return null;
        }
        TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
        tokenBufferBufferForInputBuffering.writeStartArray();
        tokenBufferBufferForInputBuffering.writeString(str);
        tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParserAsParser);
        tokenBufferBufferForInputBuffering.writeEndArray();
        JsonParser jsonParserAsParser2 = tokenBufferBufferForInputBuffering.asParser(jsonParser);
        jsonParserAsParser2.nextToken();
        return this._properties[i].getProperty().deserialize(jsonParserAsParser2, deserializationContext);
    }

    public final void _deserializeAndSet(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj, int i, String str) throws IOException {
        if (str == null) {
            deserializationContext.reportInputMismatch(this._beanType, "Internal error in external Type Id handling: `null` type id passed", new Object[0]);
        }
        JsonParser jsonParserAsParser = this._tokens[i].asParser(jsonParser);
        if (jsonParserAsParser.nextToken() == JsonToken.VALUE_NULL) {
            this._properties[i].getProperty().set(obj, null);
            return;
        }
        TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
        tokenBufferBufferForInputBuffering.writeStartArray();
        tokenBufferBufferForInputBuffering.writeString(str);
        tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParserAsParser);
        tokenBufferBufferForInputBuffering.writeEndArray();
        JsonParser jsonParserAsParser2 = tokenBufferBufferForInputBuffering.asParser(jsonParser);
        jsonParserAsParser2.nextToken();
        this._properties[i].getProperty().deserializeAndSet(jsonParserAsParser2, deserializationContext, obj);
    }

    public final Object _deserializeMissingToken(JsonParser jsonParser, DeserializationContext deserializationContext, int i, String str) throws IOException {
        TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
        tokenBufferBufferForInputBuffering.writeStartArray();
        tokenBufferBufferForInputBuffering.writeString(str);
        tokenBufferBufferForInputBuffering.writeEndArray();
        JsonParser jsonParserAsParser = tokenBufferBufferForInputBuffering.asParser(jsonParser);
        jsonParserAsParser.nextToken();
        return this._properties[i].getProperty().deserialize(jsonParserAsParser, deserializationContext);
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x00bf, code lost:
    
        return r11;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object complete(com.fasterxml.jackson.core.JsonParser r9, com.fasterxml.jackson.databind.DeserializationContext r10, java.lang.Object r11) throws java.io.IOException {
        /*
            r8 = this;
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r0 = r8._properties
            int r0 = r0.length
            r1 = 0
            r6 = r1
        L5:
            if (r6 >= r0) goto L99
            java.lang.String[] r1 = r8._typeIds
            r1 = r1[r6]
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r2 = r8._properties
            r2 = r2[r6]
            if (r1 != 0) goto L80
            com.fasterxml.jackson.databind.util.TokenBuffer[] r3 = r8._tokens
            r3 = r3[r6]
            if (r3 != 0) goto L1c
        L17:
            r3 = r9
            r4 = r10
            r5 = r11
            goto Lb8
        L1c:
            com.fasterxml.jackson.core.JsonToken r4 = r3.firstToken()
            boolean r4 = r4.isScalarValue()
            if (r4 == 0) goto L3f
            com.fasterxml.jackson.core.JsonParser r3 = r3.asParser(r9)
            r3.nextToken()
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r4 = r2.getProperty()
            com.fasterxml.jackson.databind.JavaType r5 = r4.getType()
            java.lang.Object r3 = com.fasterxml.jackson.databind.jsontype.TypeDeserializer.deserializeIfNatural(r3, r10, r5)
            if (r3 == 0) goto L3f
            r4.set(r11, r3)
            goto L17
        L3f:
            boolean r3 = r2.hasDefaultType()
            if (r3 != 0) goto L5d
            com.fasterxml.jackson.databind.JavaType r3 = r8._beanType
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r4 = r2.getProperty()
            java.lang.String r4 = r4.getName()
            java.lang.String r2 = r2.getTypePropertyName()
            java.lang.Object[] r2 = new java.lang.Object[]{r2}
            java.lang.String r5 = "Missing external type id property '%s' (and no 'defaultImpl' specified)"
            r10.reportPropertyInputMismatch(r3, r4, r5, r2)
            goto L7a
        L5d:
            java.lang.String r1 = r2.getDefaultTypeId()
            if (r1 != 0) goto L7a
            com.fasterxml.jackson.databind.JavaType r3 = r8._beanType
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r4 = r2.getProperty()
            java.lang.String r4 = r4.getName()
            java.lang.String r2 = r2.getTypePropertyName()
            java.lang.Object[] r2 = new java.lang.Object[]{r2}
            java.lang.String r5 = "Invalid default type id for property '%s': `null` returned by TypeIdResolver"
            r10.reportPropertyInputMismatch(r3, r4, r5, r2)
        L7a:
            r2 = r8
            r3 = r9
            r4 = r10
            r5 = r11
            r7 = r1
            goto Lb5
        L80:
            com.fasterxml.jackson.databind.util.TokenBuffer[] r3 = r8._tokens
            r3 = r3[r6]
            if (r3 != 0) goto L7a
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r9 = r2.getProperty()
            boolean r0 = r9.isRequired()
            if (r0 != 0) goto L9b
            com.fasterxml.jackson.databind.DeserializationFeature r0 = com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_MISSING_EXTERNAL_TYPE_ID_PROPERTY
            boolean r0 = r10.isEnabled(r0)
            if (r0 == 0) goto L99
            goto L9b
        L99:
            r5 = r11
            goto Lbf
        L9b:
            java.lang.Class r0 = r11.getClass()
            java.lang.String r1 = r9.getName()
            java.lang.String r9 = r9.getName()
            java.lang.String r2 = r2.getTypePropertyName()
            java.lang.Object[] r9 = new java.lang.Object[]{r9, r2}
            java.lang.String r2 = "Missing property '%s' for external type id '%s'"
            r10.reportPropertyInputMismatch(r0, r1, r2, r9)
            return r11
        Lb5:
            r2._deserializeAndSet(r3, r4, r5, r6, r7)
        Lb8:
            int r6 = r6 + 1
            r9 = r3
            r10 = r4
            r11 = r5
            goto L5
        Lbf:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler.complete(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext, java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00b6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean handlePropertyValue(com.fasterxml.jackson.core.JsonParser r10, com.fasterxml.jackson.databind.DeserializationContext r11, java.lang.String r12, java.lang.Object r13) throws java.io.IOException {
        /*
            r9 = this;
            java.util.Map<java.lang.String, java.lang.Object> r0 = r9._nameToPropertyIndex
            java.lang.Object r0 = r0.get(r12)
            if (r0 != 0) goto La
            r10 = 0
            return r10
        La:
            boolean r1 = r0 instanceof java.util.List
            r2 = 1
            if (r1 == 0) goto L6f
            java.util.List r0 = (java.util.List) r0
            java.util.Iterator r13 = r0.iterator()
            java.lang.Object r0 = r13.next()
            java.lang.Integer r0 = (java.lang.Integer) r0
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r1 = r9._properties
            int r3 = r0.intValue()
            r1 = r1[r3]
            boolean r12 = r1.hasTypePropertyName(r12)
            if (r12 == 0) goto L4d
            java.lang.String r11 = r10.getText()
            r10.skipChildren()
            java.lang.String[] r10 = r9._typeIds
            int r12 = r0.intValue()
            r10[r12] = r11
        L38:
            boolean r10 = r13.hasNext()
            if (r10 == 0) goto L6e
            java.lang.String[] r10 = r9._typeIds
            java.lang.Object r12 = r13.next()
            java.lang.Integer r12 = (java.lang.Integer) r12
            int r12 = r12.intValue()
            r10[r12] = r11
            goto L38
        L4d:
            com.fasterxml.jackson.databind.util.TokenBuffer r10 = r11.bufferAsCopyOfValue(r10)
            com.fasterxml.jackson.databind.util.TokenBuffer[] r11 = r9._tokens
            int r12 = r0.intValue()
            r11[r12] = r10
        L59:
            boolean r11 = r13.hasNext()
            if (r11 == 0) goto L6e
            com.fasterxml.jackson.databind.util.TokenBuffer[] r11 = r9._tokens
            java.lang.Object r12 = r13.next()
            java.lang.Integer r12 = (java.lang.Integer) r12
            int r12 = r12.intValue()
            r11[r12] = r10
            goto L59
        L6e:
            return r2
        L6f:
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r7 = r0.intValue()
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r0 = r9._properties
            r0 = r0[r7]
            boolean r12 = r0.hasTypePropertyName(r12)
            if (r12 == 0) goto L93
            java.lang.String[] r12 = r9._typeIds
            java.lang.String r0 = r10.getValueAsString()
            r12[r7] = r0
            r10.skipChildren()
            if (r13 == 0) goto Lb6
            com.fasterxml.jackson.databind.util.TokenBuffer[] r12 = r9._tokens
            r12 = r12[r7]
            if (r12 == 0) goto Lb6
            goto La3
        L93:
            com.fasterxml.jackson.databind.util.TokenBuffer r12 = r11.bufferAsCopyOfValue(r10)
            com.fasterxml.jackson.databind.util.TokenBuffer[] r0 = r9._tokens
            r0[r7] = r12
            if (r13 == 0) goto Lb6
            java.lang.String[] r12 = r9._typeIds
            r12 = r12[r7]
            if (r12 == 0) goto Lb6
        La3:
            java.lang.String[] r12 = r9._typeIds
            r8 = r12[r7]
            r0 = 0
            r12[r7] = r0
            r3 = r9
            r4 = r10
            r5 = r11
            r6 = r13
            r3._deserializeAndSet(r4, r5, r6, r7, r8)
            com.fasterxml.jackson.databind.util.TokenBuffer[] r10 = r3._tokens
            r10[r7] = r0
            goto Lb7
        Lb6:
            r3 = r9
        Lb7:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler.handlePropertyValue(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext, java.lang.String, java.lang.Object):boolean");
    }

    public boolean handleTypePropertyValue(JsonParser jsonParser, DeserializationContext deserializationContext, String str, Object obj) throws IOException {
        Object obj2 = this._nameToPropertyIndex.get(str);
        boolean z = false;
        if (obj2 == null) {
            return false;
        }
        String text = jsonParser.getText();
        if (!(obj2 instanceof List)) {
            return _handleTypePropertyValue(jsonParser, deserializationContext, str, obj, text, ((Integer) obj2).intValue());
        }
        Iterator it2 = ((List) obj2).iterator();
        while (it2.hasNext()) {
            JsonParser jsonParser2 = jsonParser;
            DeserializationContext deserializationContext2 = deserializationContext;
            String str2 = str;
            Object obj3 = obj;
            if (_handleTypePropertyValue(jsonParser2, deserializationContext2, str2, obj3, text, ((Integer) it2.next()).intValue())) {
                z = true;
            }
            jsonParser = jsonParser2;
            deserializationContext = deserializationContext2;
            str = str2;
            obj = obj3;
        }
        return z;
    }

    public ExternalTypeHandler start() {
        return new ExternalTypeHandler(this);
    }

    public ExternalTypeHandler(ExternalTypeHandler externalTypeHandler) {
        this._beanType = externalTypeHandler._beanType;
        ExtTypedProperty[] extTypedPropertyArr = externalTypeHandler._properties;
        this._properties = extTypedPropertyArr;
        this._nameToPropertyIndex = externalTypeHandler._nameToPropertyIndex;
        int length = extTypedPropertyArr.length;
        this._typeIds = new String[length];
        this._tokens = new TokenBuffer[length];
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00c0 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object complete(com.fasterxml.jackson.core.JsonParser r11, com.fasterxml.jackson.databind.DeserializationContext r12, com.fasterxml.jackson.databind.deser.impl.PropertyValueBuffer r13, com.fasterxml.jackson.databind.deser.impl.PropertyBasedCreator r14) throws java.io.IOException {
        /*
            r10 = this;
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r0 = r10._properties
            int r0 = r0.length
            java.lang.Object[] r1 = new java.lang.Object[r0]
            r2 = 0
            r3 = r2
        L7:
            if (r3 >= r0) goto Lc4
            java.lang.String[] r4 = r10._typeIds
            r4 = r4[r3]
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r5 = r10._properties
            r5 = r5[r3]
            if (r4 != 0) goto L45
            com.fasterxml.jackson.databind.util.TokenBuffer[] r6 = r10._tokens
            r6 = r6[r3]
            if (r6 == 0) goto Lc0
            com.fasterxml.jackson.core.JsonToken r6 = r6.firstToken()
            com.fasterxml.jackson.core.JsonToken r7 = com.fasterxml.jackson.core.JsonToken.VALUE_NULL
            if (r6 != r7) goto L23
            goto Lc0
        L23:
            boolean r6 = r5.hasDefaultType()
            if (r6 != 0) goto L41
            com.fasterxml.jackson.databind.JavaType r6 = r10._beanType
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r7 = r5.getProperty()
            java.lang.String r7 = r7.getName()
            java.lang.String r8 = r5.getTypePropertyName()
            java.lang.Object[] r8 = new java.lang.Object[]{r8}
            java.lang.String r9 = "Missing external type id property '%s'"
            r12.reportPropertyInputMismatch(r6, r7, r9, r8)
            goto L45
        L41:
            java.lang.String r4 = r5.getDefaultTypeId()
        L45:
            com.fasterxml.jackson.databind.util.TokenBuffer[] r6 = r10._tokens
            r6 = r6[r3]
            if (r6 == 0) goto L52
            java.lang.Object r6 = r10._deserialize(r11, r12, r3, r4)
            r1[r3] = r6
            goto L7f
        L52:
            com.fasterxml.jackson.databind.DeserializationFeature r6 = com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_MISSING_EXTERNAL_TYPE_ID_PROPERTY
            boolean r6 = r12.isEnabled(r6)
            if (r6 == 0) goto L79
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r6 = r5.getProperty()
            com.fasterxml.jackson.databind.JavaType r7 = r10._beanType
            java.lang.String r8 = r6.getName()
            java.lang.String r6 = r6.getName()
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r9 = r10._properties
            r9 = r9[r3]
            java.lang.String r9 = r9.getTypePropertyName()
            java.lang.Object[] r6 = new java.lang.Object[]{r6, r9}
            java.lang.String r9 = "Missing property '%s' for external type id '%s'"
            r12.reportPropertyInputMismatch(r7, r8, r9, r6)
        L79:
            java.lang.Object r6 = r10._deserializeMissingToken(r11, r12, r3, r4)
            r1[r3] = r6
        L7f:
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r6 = r5.getProperty()
            int r7 = r6.getCreatorIndex()
            if (r7 < 0) goto Lc0
            r7 = r1[r3]
            r13.assignParameter(r6, r7)
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r5 = r5.getTypeProperty()
            if (r5 == 0) goto Lc0
            int r6 = r5.getCreatorIndex()
            if (r6 < 0) goto Lc0
            com.fasterxml.jackson.databind.JavaType r6 = r5.getType()
            java.lang.Class<java.lang.String> r7 = java.lang.String.class
            boolean r6 = r6.hasRawClass(r7)
            if (r6 == 0) goto La7
            goto Lbd
        La7:
            com.fasterxml.jackson.databind.util.TokenBuffer r6 = r12.bufferForInputBuffering(r11)
            r6.writeString(r4)
            com.fasterxml.jackson.databind.JsonDeserializer r4 = r5.getValueDeserializer()
            com.fasterxml.jackson.core.JsonParser r7 = r6.asParserOnFirstToken()
            java.lang.Object r4 = r4.deserialize(r7, r12)
            r6.close()
        Lbd:
            r13.assignParameter(r5, r4)
        Lc0:
            int r3 = r3 + 1
            goto L7
        Lc4:
            java.lang.Object r11 = r14.build(r12, r13)
        Lc8:
            if (r2 >= r0) goto Le0
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler$ExtTypedProperty[] r12 = r10._properties
            r12 = r12[r2]
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r12 = r12.getProperty()
            int r13 = r12.getCreatorIndex()
            if (r13 >= 0) goto Ldd
            r13 = r1[r2]
            r12.set(r11, r13)
        Ldd:
            int r2 = r2 + 1
            goto Lc8
        Le0:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler.complete(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext, com.fasterxml.jackson.databind.deser.impl.PropertyValueBuffer, com.fasterxml.jackson.databind.deser.impl.PropertyBasedCreator):java.lang.Object");
    }
}
