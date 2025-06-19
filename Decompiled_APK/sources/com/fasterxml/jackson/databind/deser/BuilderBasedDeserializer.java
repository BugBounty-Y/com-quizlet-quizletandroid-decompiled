package com.fasterxml.jackson.databind.deser;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.deser.impl.BeanAsArrayBuilderDeserializer;
import com.fasterxml.jackson.databind.deser.impl.BeanPropertyMap;
import com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler;
import com.fasterxml.jackson.databind.deser.impl.ObjectIdReader;
import com.fasterxml.jackson.databind.deser.impl.PropertyBasedCreator;
import com.fasterxml.jackson.databind.deser.impl.PropertyValueBuffer;
import com.fasterxml.jackson.databind.introspect.AnnotatedMethod;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.IgnorePropertiesUtil;
import com.fasterxml.jackson.databind.util.NameTransformer;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

/* loaded from: classes.dex */
public class BuilderBasedDeserializer extends BeanDeserializerBase {
    protected final AnnotatedMethod _buildMethod;
    protected final JavaType _targetType;

    /* renamed from: com.fasterxml.jackson.databind.deser.BuilderBasedDeserializer$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$fasterxml$jackson$databind$cfg$CoercionAction;

        static {
            int[] iArr = new int[CoercionAction.values().length];
            $SwitchMap$com$fasterxml$jackson$databind$cfg$CoercionAction = iArr;
            try {
                iArr[CoercionAction.AsEmpty.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$databind$cfg$CoercionAction[CoercionAction.AsNull.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$databind$cfg$CoercionAction[CoercionAction.TryConvert.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    public BuilderBasedDeserializer(BeanDeserializerBuilder beanDeserializerBuilder, BeanDescription beanDescription, JavaType javaType, BeanPropertyMap beanPropertyMap, Map<String, SettableBeanProperty> map, Set<String> set, boolean z, Set<String> set2, boolean z2) {
        super(beanDeserializerBuilder, beanDescription, beanPropertyMap, map, set, z, set2, z2);
        this._targetType = javaType;
        this._buildMethod = beanDeserializerBuilder.getBuildMethod();
        if (this._objectIdReader == null) {
            return;
        }
        throw new IllegalArgumentException("Cannot use Object Id with Builder-based deserialization (type " + beanDescription.getType() + ")");
    }

    private final Object vanillaDeserialize(JsonParser jsonParser, DeserializationContext deserializationContext, JsonToken jsonToken) throws IOException {
        Object objCreateUsingDefault = this._valueInstantiator.createUsingDefault(deserializationContext);
        while (jsonParser.currentToken() == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind != null) {
                try {
                    objCreateUsingDefault = settableBeanPropertyFind.deserializeSetAndReturn(jsonParser, deserializationContext, objCreateUsingDefault);
                } catch (Exception e) {
                    wrapAndThrow(e, objCreateUsingDefault, strCurrentName, deserializationContext);
                }
            } else {
                handleUnknownVanilla(jsonParser, deserializationContext, objCreateUsingDefault, strCurrentName);
            }
            jsonParser.nextToken();
        }
        return objCreateUsingDefault;
    }

    public final Object _deserialize(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj) throws UnsupportedOperationException, IOException, IllegalArgumentException {
        Class<?> activeView;
        if (this._injectables != null) {
            injectValues(deserializationContext, obj);
        }
        if (this._unwrappedPropertyHandler != null) {
            if (jsonParser.hasToken(JsonToken.START_OBJECT)) {
                jsonParser.nextToken();
            }
            TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
            tokenBufferBufferForInputBuffering.writeStartObject();
            return deserializeWithUnwrapped(jsonParser, deserializationContext, obj, tokenBufferBufferForInputBuffering);
        }
        if (this._externalTypeIdHandler != null) {
            return deserializeWithExternalTypeId(jsonParser, deserializationContext, obj);
        }
        if (this._needViewProcesing && (activeView = deserializationContext.getActiveView()) != null) {
            return deserializeWithView(jsonParser, deserializationContext, obj, activeView);
        }
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        if (jsonTokenCurrentToken == JsonToken.START_OBJECT) {
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind != null) {
                try {
                    obj = settableBeanPropertyFind.deserializeSetAndReturn(jsonParser, deserializationContext, obj);
                } catch (Exception e) {
                    wrapAndThrow(e, obj, strCurrentName, deserializationContext);
                }
            } else {
                handleUnknownVanilla(jsonParser, deserializationContext, obj, strCurrentName);
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        return obj;
    }

    @Override // com.fasterxml.jackson.databind.deser.std.StdDeserializer
    public Object _deserializeFromArray(JsonParser jsonParser, DeserializationContext deserializationContext) throws UnsupportedOperationException, IOException, IllegalArgumentException {
        JsonParser jsonParser2;
        DeserializationContext deserializationContext2;
        JsonDeserializer<Object> jsonDeserializer = this._arrayDelegateDeserializer;
        if (jsonDeserializer != null || (jsonDeserializer = this._delegateDeserializer) != null) {
            Object objCreateUsingArrayDelegate = this._valueInstantiator.createUsingArrayDelegate(deserializationContext, jsonDeserializer.deserialize(jsonParser, deserializationContext));
            if (this._injectables != null) {
                injectValues(deserializationContext, objCreateUsingArrayDelegate);
            }
            return finishBuild(deserializationContext, objCreateUsingArrayDelegate);
        }
        CoercionAction coercionAction_findCoercionFromEmptyArray = _findCoercionFromEmptyArray(deserializationContext);
        boolean zIsEnabled = deserializationContext.isEnabled(DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS);
        if (zIsEnabled || coercionAction_findCoercionFromEmptyArray != CoercionAction.Fail) {
            JsonToken jsonTokenNextToken = jsonParser.nextToken();
            JsonToken jsonToken = JsonToken.END_ARRAY;
            if (jsonTokenNextToken == jsonToken) {
                int i = AnonymousClass1.$SwitchMap$com$fasterxml$jackson$databind$cfg$CoercionAction[coercionAction_findCoercionFromEmptyArray.ordinal()];
                return i != 1 ? (i == 2 || i == 3) ? getNullValue(deserializationContext) : deserializationContext.handleUnexpectedToken(getValueType(deserializationContext), JsonToken.START_ARRAY, jsonParser, (String) null, new Object[0]) : getEmptyValue(deserializationContext);
            }
            jsonParser2 = jsonParser;
            deserializationContext2 = deserializationContext;
            if (zIsEnabled) {
                Object objDeserialize = deserialize(jsonParser2, deserializationContext2);
                if (jsonParser2.nextToken() != jsonToken) {
                    handleMissingEndArrayForSingle(jsonParser2, deserializationContext2);
                }
                return objDeserialize;
            }
        } else {
            jsonParser2 = jsonParser;
            deserializationContext2 = deserializationContext;
        }
        return deserializationContext2.handleUnexpectedToken(getValueType(deserializationContext2), jsonParser2);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public Object _deserializeUsingPropertyBased(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        Object objWrapInstantiationProblem;
        JsonParser jsonParser2;
        DeserializationContext deserializationContext2;
        PropertyBasedCreator propertyBasedCreator = this._propertyBasedCreator;
        PropertyValueBuffer propertyValueBufferStartBuilding = propertyBasedCreator.startBuilding(jsonParser, deserializationContext, this._objectIdReader);
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        TokenBuffer tokenBufferBufferForInputBuffering = null;
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFindCreatorProperty = propertyBasedCreator.findCreatorProperty(strCurrentName);
            if (propertyValueBufferStartBuilding.readIdProperty(strCurrentName) && settableBeanPropertyFindCreatorProperty == null) {
                jsonParser2 = jsonParser;
                deserializationContext2 = deserializationContext;
            } else if (settableBeanPropertyFindCreatorProperty != null) {
                if (activeView != null && !settableBeanPropertyFindCreatorProperty.visibleInView(activeView)) {
                    jsonParser.skipChildren();
                } else if (propertyValueBufferStartBuilding.assignParameter(settableBeanPropertyFindCreatorProperty, settableBeanPropertyFindCreatorProperty.deserialize(jsonParser, deserializationContext))) {
                    jsonParser.nextToken();
                    try {
                        Object objBuild = propertyBasedCreator.build(deserializationContext, propertyValueBufferStartBuilding);
                        if (objBuild.getClass() != this._beanType.getRawClass()) {
                            return handlePolymorphic(jsonParser, deserializationContext, jsonParser.streamReadConstraints(), objBuild, tokenBufferBufferForInputBuffering);
                        }
                        JsonParser jsonParser3 = jsonParser;
                        DeserializationContext deserializationContext3 = deserializationContext;
                        if (tokenBufferBufferForInputBuffering != null) {
                            objBuild = handleUnknownProperties(deserializationContext3, objBuild, tokenBufferBufferForInputBuffering);
                        }
                        return _deserialize(jsonParser3, deserializationContext3, objBuild);
                    } catch (Exception e) {
                        jsonParser2 = jsonParser;
                        deserializationContext2 = deserializationContext;
                        wrapAndThrow(e, this._beanType.getRawClass(), strCurrentName, deserializationContext2);
                    }
                }
                jsonParser2 = jsonParser;
                deserializationContext2 = deserializationContext;
            } else {
                jsonParser2 = jsonParser;
                deserializationContext2 = deserializationContext;
                SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
                if (settableBeanPropertyFind != null) {
                    propertyValueBufferStartBuilding.bufferProperty(settableBeanPropertyFind, settableBeanPropertyFind.deserialize(jsonParser2, deserializationContext2));
                } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                    handleIgnoredProperty(jsonParser2, deserializationContext2, handledType(), strCurrentName);
                } else {
                    SettableAnyProperty settableAnyProperty = this._anySetter;
                    if (settableAnyProperty != null) {
                        propertyValueBufferStartBuilding.bufferAnyProperty(settableAnyProperty, strCurrentName, settableAnyProperty.deserialize(jsonParser2, deserializationContext2));
                    } else {
                        if (tokenBufferBufferForInputBuffering == null) {
                            tokenBufferBufferForInputBuffering = deserializationContext2.bufferForInputBuffering(jsonParser2);
                        }
                        tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                        tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParser2);
                    }
                }
            }
            jsonTokenCurrentToken = jsonParser2.nextToken();
            jsonParser = jsonParser2;
            deserializationContext = deserializationContext2;
        }
        JsonParser jsonParser4 = jsonParser;
        DeserializationContext deserializationContext4 = deserializationContext;
        try {
            objWrapInstantiationProblem = propertyBasedCreator.build(deserializationContext4, propertyValueBufferStartBuilding);
        } catch (Exception e2) {
            objWrapInstantiationProblem = wrapInstantiationProblem(e2, deserializationContext4);
        }
        Object obj = objWrapInstantiationProblem;
        return tokenBufferBufferForInputBuffering != null ? obj.getClass() != this._beanType.getRawClass() ? handlePolymorphic(null, deserializationContext4, jsonParser4.streamReadConstraints(), obj, tokenBufferBufferForInputBuffering) : handleUnknownProperties(deserializationContext4, obj, tokenBufferBufferForInputBuffering) : obj;
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase asArrayDeserializer() {
        return new BeanAsArrayBuilderDeserializer(this, this._targetType, this._beanProperties.getPropertiesInInsertionOrder(), this._buildMethod);
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        if (jsonParser.isExpectedStartObjectToken()) {
            return this._vanillaProcessing ? finishBuild(deserializationContext, vanillaDeserialize(jsonParser, deserializationContext, jsonParser.nextToken())) : finishBuild(deserializationContext, deserializeFromObject(jsonParser, deserializationContext));
        }
        switch (jsonParser.currentTokenId()) {
            case 2:
            case 5:
                return finishBuild(deserializationContext, deserializeFromObject(jsonParser, deserializationContext));
            case 3:
                return _deserializeFromArray(jsonParser, deserializationContext);
            case 4:
            case 11:
            default:
                return deserializationContext.handleUnexpectedToken(getValueType(deserializationContext), jsonParser);
            case 6:
                return finishBuild(deserializationContext, deserializeFromString(jsonParser, deserializationContext));
            case 7:
                return finishBuild(deserializationContext, deserializeFromNumber(jsonParser, deserializationContext));
            case 8:
                return finishBuild(deserializationContext, deserializeFromDouble(jsonParser, deserializationContext));
            case 9:
            case 10:
                return finishBuild(deserializationContext, deserializeFromBoolean(jsonParser, deserializationContext));
            case 12:
                return jsonParser.getEmbeddedObject();
        }
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public Object deserializeFromObject(JsonParser jsonParser, DeserializationContext deserializationContext) throws UnsupportedOperationException, IOException, IllegalArgumentException {
        Class<?> activeView;
        if (this._nonStandardCreation) {
            return this._unwrappedPropertyHandler != null ? deserializeWithUnwrapped(jsonParser, deserializationContext) : this._externalTypeIdHandler != null ? deserializeWithExternalTypeId(jsonParser, deserializationContext) : deserializeFromObjectUsingNonDefault(jsonParser, deserializationContext);
        }
        Object objCreateUsingDefault = this._valueInstantiator.createUsingDefault(deserializationContext);
        if (this._injectables != null) {
            injectValues(deserializationContext, objCreateUsingDefault);
        }
        if (this._needViewProcesing && (activeView = deserializationContext.getActiveView()) != null) {
            return deserializeWithView(jsonParser, deserializationContext, objCreateUsingDefault, activeView);
        }
        while (jsonParser.currentToken() == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind != null) {
                try {
                    objCreateUsingDefault = settableBeanPropertyFind.deserializeSetAndReturn(jsonParser, deserializationContext, objCreateUsingDefault);
                } catch (Exception e) {
                    wrapAndThrow(e, objCreateUsingDefault, strCurrentName, deserializationContext);
                }
            } else {
                handleUnknownVanilla(jsonParser, deserializationContext, objCreateUsingDefault, strCurrentName);
            }
            jsonParser.nextToken();
        }
        return objCreateUsingDefault;
    }

    public Object deserializeUsingPropertyBasedWithExternalTypeId(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        JavaType javaType = this._targetType;
        return deserializationContext.reportBadDefinition(javaType, String.format("Deserialization (of %s) with Builder, External type id, @JsonCreator not yet implemented", javaType));
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x002a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object deserializeUsingPropertyBasedWithUnwrapped(com.fasterxml.jackson.core.JsonParser r10, com.fasterxml.jackson.databind.DeserializationContext r11) throws java.io.IOException {
        /*
            r9 = this;
            com.fasterxml.jackson.databind.deser.impl.PropertyBasedCreator r1 = r9._propertyBasedCreator
            com.fasterxml.jackson.databind.deser.impl.ObjectIdReader r0 = r9._objectIdReader
            com.fasterxml.jackson.databind.deser.impl.PropertyValueBuffer r2 = r1.startBuilding(r10, r11, r0)
            com.fasterxml.jackson.databind.util.TokenBuffer r8 = r11.bufferForInputBuffering(r10)
            r8.writeStartObject()
            com.fasterxml.jackson.core.JsonToken r0 = r10.currentToken()
        L13:
            com.fasterxml.jackson.core.JsonToken r3 = com.fasterxml.jackson.core.JsonToken.FIELD_NAME
            if (r0 != r3) goto Lb0
            java.lang.String r3 = r10.currentName()
            r10.nextToken()
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r0 = r1.findCreatorProperty(r3)
            boolean r4 = r2.readIdProperty(r3)
            if (r4 == 0) goto L2f
            if (r0 != 0) goto L2f
        L2a:
            r4 = r10
            r5 = r11
            r11 = r9
            goto La8
        L2f:
            if (r0 == 0) goto L72
            java.lang.Object r4 = r0.deserialize(r10, r11)
            boolean r0 = r2.assignParameter(r0, r4)
            if (r0 == 0) goto L2a
            r10.nextToken()
            java.lang.Object r7 = r1.build(r11, r2)     // Catch: java.lang.Exception -> L63
            java.lang.Class r0 = r7.getClass()
            com.fasterxml.jackson.databind.JavaType r1 = r9._beanType
            java.lang.Class r1 = r1.getRawClass()
            if (r0 == r1) goto L5b
            com.fasterxml.jackson.core.StreamReadConstraints r6 = r10.streamReadConstraints()
            r3 = r9
            r4 = r10
            r5 = r11
            java.lang.Object r10 = r3.handlePolymorphic(r4, r5, r6, r7, r8)
            r11 = r3
            return r10
        L5b:
            r4 = r10
            r5 = r11
            r11 = r9
            java.lang.Object r10 = r9.deserializeWithUnwrapped(r4, r5, r7, r8)
            return r10
        L63:
            r0 = move-exception
            r4 = r10
            r5 = r11
            r11 = r9
            r10 = r0
            com.fasterxml.jackson.databind.JavaType r0 = r11._beanType
            java.lang.Class r0 = r0.getRawClass()
            r9.wrapAndThrow(r10, r0, r3, r5)
            goto La8
        L72:
            r4 = r10
            r5 = r11
            r11 = r9
            com.fasterxml.jackson.databind.deser.impl.BeanPropertyMap r10 = r11._beanProperties
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r10 = r10.find(r3)
            if (r10 == 0) goto L85
            java.lang.Object r0 = r10.deserialize(r4, r5)
            r2.bufferProperty(r10, r0)
            goto La8
        L85:
            java.util.Set<java.lang.String> r10 = r11._ignorableProps
            java.util.Set<java.lang.String> r0 = r11._includableProps
            boolean r10 = com.fasterxml.jackson.databind.util.IgnorePropertiesUtil.shouldIgnore(r3, r10, r0)
            if (r10 == 0) goto L97
            java.lang.Class r10 = r9.handledType()
            r9.handleIgnoredProperty(r4, r5, r10, r3)
            goto La8
        L97:
            r8.writeFieldName(r3)
            r8.copyCurrentStructure(r4)
            com.fasterxml.jackson.databind.deser.SettableAnyProperty r10 = r11._anySetter
            if (r10 == 0) goto La8
            java.lang.Object r0 = r10.deserialize(r4, r5)
            r2.bufferAnyProperty(r10, r3, r0)
        La8:
            com.fasterxml.jackson.core.JsonToken r0 = r4.nextToken()
            r10 = r4
            r11 = r5
            goto L13
        Lb0:
            r4 = r10
            r5 = r11
            r11 = r9
            r8.writeEndObject()
            java.lang.Object r10 = r1.build(r5, r2)     // Catch: java.lang.Exception -> Lc1
            com.fasterxml.jackson.databind.deser.impl.UnwrappedPropertyHandler r0 = r11._unwrappedPropertyHandler
            java.lang.Object r10 = r0.processUnwrapped(r4, r5, r10, r8)
            return r10
        Lc1:
            r0 = move-exception
            r10 = r0
            java.lang.Object r10 = r9.wrapInstantiationProblem(r10, r5)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.BuilderBasedDeserializer.deserializeUsingPropertyBasedWithUnwrapped(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext):java.lang.Object");
    }

    public Object deserializeWithExternalTypeId(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        return this._propertyBasedCreator != null ? deserializeUsingPropertyBasedWithExternalTypeId(jsonParser, deserializationContext) : deserializeWithExternalTypeId(jsonParser, deserializationContext, this._valueInstantiator.createUsingDefault(deserializationContext));
    }

    public Object deserializeWithUnwrapped(JsonParser jsonParser, DeserializationContext deserializationContext) throws UnsupportedOperationException, IOException, IllegalArgumentException {
        JsonDeserializer<Object> jsonDeserializer = this._delegateDeserializer;
        if (jsonDeserializer != null) {
            return this._valueInstantiator.createUsingDelegate(deserializationContext, jsonDeserializer.deserialize(jsonParser, deserializationContext));
        }
        if (this._propertyBasedCreator != null) {
            return deserializeUsingPropertyBasedWithUnwrapped(jsonParser, deserializationContext);
        }
        TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
        tokenBufferBufferForInputBuffering.writeStartObject();
        Object objCreateUsingDefault = this._valueInstantiator.createUsingDefault(deserializationContext);
        if (this._injectables != null) {
            injectValues(deserializationContext, objCreateUsingDefault);
        }
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        while (jsonParser.currentToken() == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind != null) {
                if (activeView == null || settableBeanPropertyFind.visibleInView(activeView)) {
                    try {
                        objCreateUsingDefault = settableBeanPropertyFind.deserializeSetAndReturn(jsonParser, deserializationContext, objCreateUsingDefault);
                    } catch (Exception e) {
                        wrapAndThrow(e, objCreateUsingDefault, strCurrentName, deserializationContext);
                    }
                } else {
                    jsonParser.skipChildren();
                }
            } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                handleIgnoredProperty(jsonParser, deserializationContext, objCreateUsingDefault, strCurrentName);
            } else {
                tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParser);
                SettableAnyProperty settableAnyProperty = this._anySetter;
                if (settableAnyProperty != null) {
                    try {
                        settableAnyProperty.deserializeAndSet(jsonParser, deserializationContext, objCreateUsingDefault, strCurrentName);
                    } catch (Exception e2) {
                        wrapAndThrow(e2, objCreateUsingDefault, strCurrentName, deserializationContext);
                    }
                }
            }
            jsonParser.nextToken();
        }
        tokenBufferBufferForInputBuffering.writeEndObject();
        return this._unwrappedPropertyHandler.processUnwrapped(jsonParser, deserializationContext, objCreateUsingDefault, tokenBufferBufferForInputBuffering);
    }

    public final Object deserializeWithView(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj, Class<?> cls) throws IOException {
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind == null) {
                handleUnknownVanilla(jsonParser, deserializationContext, obj, strCurrentName);
            } else if (settableBeanPropertyFind.visibleInView(cls)) {
                try {
                    obj = settableBeanPropertyFind.deserializeSetAndReturn(jsonParser, deserializationContext, obj);
                } catch (Exception e) {
                    wrapAndThrow(e, obj, strCurrentName, deserializationContext);
                }
            } else {
                if (deserializationContext.isEnabled(DeserializationFeature.FAIL_ON_UNEXPECTED_VIEW_PROPERTIES)) {
                    Class<?> clsHandledType = handledType();
                    String strNameOf = ClassUtil.nameOf(handledType());
                    String name = settableBeanPropertyFind.getName();
                    deserializationContext.reportInputMismatch(clsHandledType, a.t(AbstractC0147y.h("Input mismatch while deserializing ", strNameOf, ". Property '", name, "' is not part of current active view '"), cls.getName(), "' (disable 'DeserializationFeature.FAIL_ON_UNEXPECTED_VIEW_PROPERTIES' to allow)"), new Object[0]);
                }
                jsonParser.skipChildren();
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        return obj;
    }

    public Object finishBuild(DeserializationContext deserializationContext, Object obj) throws IOException {
        AnnotatedMethod annotatedMethod = this._buildMethod;
        if (annotatedMethod == null) {
            return obj;
        }
        try {
            return annotatedMethod.getMember().invoke(obj, null);
        } catch (Exception e) {
            return wrapInstantiationProblem(e, deserializationContext);
        }
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase, com.fasterxml.jackson.databind.JsonDeserializer
    public Boolean supportsUpdate(DeserializationConfig deserializationConfig) {
        return Boolean.FALSE;
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase, com.fasterxml.jackson.databind.JsonDeserializer
    public JsonDeserializer<Object> unwrappingDeserializer(NameTransformer nameTransformer) {
        return new BuilderBasedDeserializer(this, nameTransformer);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase withBeanProperties(BeanPropertyMap beanPropertyMap) {
        return new BuilderBasedDeserializer(this, beanPropertyMap);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase withByNameInclusion(Set<String> set, Set<String> set2) {
        return new BuilderBasedDeserializer(this, set, set2);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase withIgnoreAllUnknown(boolean z) {
        return new BuilderBasedDeserializer(this, z);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase withObjectIdReader(ObjectIdReader objectIdReader) {
        return new BuilderBasedDeserializer(this, objectIdReader);
    }

    public Object deserializeWithExternalTypeId(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj) throws IOException {
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        ExternalTypeHandler externalTypeHandlerStart = this._externalTypeIdHandler.start();
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            JsonToken jsonTokenNextToken = jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind != null) {
                if (jsonTokenNextToken.isScalarValue()) {
                    externalTypeHandlerStart.handleTypePropertyValue(jsonParser, deserializationContext, strCurrentName, obj);
                }
                if (activeView != null && !settableBeanPropertyFind.visibleInView(activeView)) {
                    jsonParser.skipChildren();
                } else {
                    try {
                        obj = settableBeanPropertyFind.deserializeSetAndReturn(jsonParser, deserializationContext, obj);
                    } catch (Exception e) {
                        wrapAndThrow(e, obj, strCurrentName, deserializationContext);
                    }
                }
            } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                handleIgnoredProperty(jsonParser, deserializationContext, obj, strCurrentName);
            } else if (!externalTypeHandlerStart.handlePropertyValue(jsonParser, deserializationContext, strCurrentName, obj)) {
                SettableAnyProperty settableAnyProperty = this._anySetter;
                if (settableAnyProperty != null) {
                    try {
                        settableAnyProperty.deserializeAndSet(jsonParser, deserializationContext, obj, strCurrentName);
                    } catch (Exception e2) {
                        wrapAndThrow(e2, obj, strCurrentName, deserializationContext);
                    }
                } else {
                    handleUnknownProperty(jsonParser, deserializationContext, obj, strCurrentName);
                }
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        return externalTypeHandlerStart.complete(jsonParser, deserializationContext, obj);
    }

    public BuilderBasedDeserializer(BuilderBasedDeserializer builderBasedDeserializer, boolean z) {
        super(builderBasedDeserializer, z);
        this._buildMethod = builderBasedDeserializer._buildMethod;
        this._targetType = builderBasedDeserializer._targetType;
    }

    public BuilderBasedDeserializer(BuilderBasedDeserializer builderBasedDeserializer, NameTransformer nameTransformer) {
        super(builderBasedDeserializer, nameTransformer);
        this._buildMethod = builderBasedDeserializer._buildMethod;
        this._targetType = builderBasedDeserializer._targetType;
    }

    public BuilderBasedDeserializer(BuilderBasedDeserializer builderBasedDeserializer, ObjectIdReader objectIdReader) {
        super(builderBasedDeserializer, objectIdReader);
        this._buildMethod = builderBasedDeserializer._buildMethod;
        this._targetType = builderBasedDeserializer._targetType;
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj) throws IOException {
        JavaType javaType = this._targetType;
        Class<?> clsHandledType = handledType();
        Class<?> cls = obj.getClass();
        if (clsHandledType.isAssignableFrom(cls)) {
            return deserializationContext.reportBadDefinition(javaType, String.format("Deserialization of %s by passing existing Builder (%s) instance not supported", javaType, clsHandledType.getName()));
        }
        return deserializationContext.reportBadDefinition(javaType, String.format("Deserialization of %s by passing existing instance (of %s) not supported", javaType, cls.getName()));
    }

    public BuilderBasedDeserializer(BuilderBasedDeserializer builderBasedDeserializer, Set<String> set, Set<String> set2) {
        super(builderBasedDeserializer, set, set2);
        this._buildMethod = builderBasedDeserializer._buildMethod;
        this._targetType = builderBasedDeserializer._targetType;
    }

    public BuilderBasedDeserializer(BuilderBasedDeserializer builderBasedDeserializer, BeanPropertyMap beanPropertyMap) {
        super(builderBasedDeserializer, beanPropertyMap);
        this._buildMethod = builderBasedDeserializer._buildMethod;
        this._targetType = builderBasedDeserializer._targetType;
    }

    public Object deserializeWithUnwrapped(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj, TokenBuffer tokenBuffer) throws IOException {
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            jsonParser.nextToken();
            if (settableBeanPropertyFind != null) {
                if (activeView != null && !settableBeanPropertyFind.visibleInView(activeView)) {
                    jsonParser.skipChildren();
                } else {
                    try {
                        obj = settableBeanPropertyFind.deserializeSetAndReturn(jsonParser, deserializationContext, obj);
                    } catch (Exception e) {
                        wrapAndThrow(e, obj, strCurrentName, deserializationContext);
                    }
                }
            } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                handleIgnoredProperty(jsonParser, deserializationContext, obj, strCurrentName);
            } else {
                tokenBuffer.writeFieldName(strCurrentName);
                tokenBuffer.copyCurrentStructure(jsonParser);
                SettableAnyProperty settableAnyProperty = this._anySetter;
                if (settableAnyProperty != null) {
                    settableAnyProperty.deserializeAndSet(jsonParser, deserializationContext, obj, strCurrentName);
                }
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        tokenBuffer.writeEndObject();
        return this._unwrappedPropertyHandler.processUnwrapped(jsonParser, deserializationContext, obj, tokenBuffer);
    }
}
