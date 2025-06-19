package com.fasterxml.jackson.databind.deser;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.deser.impl.BeanAsArrayDeserializer;
import com.fasterxml.jackson.databind.deser.impl.BeanPropertyMap;
import com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler;
import com.fasterxml.jackson.databind.deser.impl.MethodProperty;
import com.fasterxml.jackson.databind.deser.impl.ObjectIdReader;
import com.fasterxml.jackson.databind.deser.impl.PropertyBasedCreator;
import com.fasterxml.jackson.databind.deser.impl.PropertyValueBuffer;
import com.fasterxml.jackson.databind.deser.impl.ReadableObjectId;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.IgnorePropertiesUtil;
import com.fasterxml.jackson.databind.util.NameTransformer;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* loaded from: classes.dex */
public class BeanDeserializer extends BeanDeserializerBase implements Serializable {
    private volatile transient NameTransformer _currentlyTransforming;

    /* renamed from: com.fasterxml.jackson.databind.deser.BeanDeserializer$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$fasterxml$jackson$core$JsonToken;
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
            int[] iArr2 = new int[JsonToken.values().length];
            $SwitchMap$com$fasterxml$jackson$core$JsonToken = iArr2;
            try {
                iArr2[JsonToken.VALUE_STRING.ordinal()] = 1;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.VALUE_NUMBER_INT.ordinal()] = 2;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.VALUE_NUMBER_FLOAT.ordinal()] = 3;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.VALUE_EMBEDDED_OBJECT.ordinal()] = 4;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.VALUE_TRUE.ordinal()] = 5;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.VALUE_FALSE.ordinal()] = 6;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.VALUE_NULL.ordinal()] = 7;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.START_ARRAY.ordinal()] = 8;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.FIELD_NAME.ordinal()] = 9;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                $SwitchMap$com$fasterxml$jackson$core$JsonToken[JsonToken.END_OBJECT.ordinal()] = 10;
            } catch (NoSuchFieldError unused13) {
            }
        }
    }

    public static class BeanReferring extends ReadableObjectId.Referring {
        private Object _bean;
        private final DeserializationContext _context;
        private final SettableBeanProperty _prop;

        public BeanReferring(DeserializationContext deserializationContext, UnresolvedForwardReference unresolvedForwardReference, JavaType javaType, PropertyValueBuffer propertyValueBuffer, SettableBeanProperty settableBeanProperty) {
            super(unresolvedForwardReference, javaType);
            this._context = deserializationContext;
            this._prop = settableBeanProperty;
        }

        public void setBean(Object obj) {
            this._bean = obj;
        }
    }

    public BeanDeserializer(BeanDeserializerBuilder beanDeserializerBuilder, BeanDescription beanDescription, BeanPropertyMap beanPropertyMap, Map<String, SettableBeanProperty> map, HashSet<String> hashSet, boolean z, Set<String> set, boolean z2) {
        super(beanDeserializerBuilder, beanDescription, beanPropertyMap, map, hashSet, z, set, z2);
    }

    private BeanReferring handleUnresolvedReference(DeserializationContext deserializationContext, SettableBeanProperty settableBeanProperty, PropertyValueBuffer propertyValueBuffer, UnresolvedForwardReference unresolvedForwardReference) throws JsonMappingException {
        BeanReferring beanReferring = new BeanReferring(deserializationContext, unresolvedForwardReference, settableBeanProperty.getType(), propertyValueBuffer, settableBeanProperty);
        unresolvedForwardReference.getRoid().appendReferring(beanReferring);
        return beanReferring;
    }

    private final Object vanillaDeserialize(JsonParser jsonParser, DeserializationContext deserializationContext, JsonToken jsonToken) throws IOException {
        Object objCreateUsingDefault = this._valueInstantiator.createUsingDefault(deserializationContext);
        if (jsonParser.hasTokenId(5)) {
            jsonParser.assignCurrentValue(objCreateUsingDefault);
            String strCurrentName = jsonParser.currentName();
            do {
                jsonParser.nextToken();
                SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
                if (settableBeanPropertyFind != null) {
                    try {
                        settableBeanPropertyFind.deserializeAndSet(jsonParser, deserializationContext, objCreateUsingDefault);
                    } catch (Exception e) {
                        wrapAndThrow(e, objCreateUsingDefault, strCurrentName, deserializationContext);
                    }
                } else {
                    handleUnknownVanilla(jsonParser, deserializationContext, objCreateUsingDefault, strCurrentName);
                }
                strCurrentName = jsonParser.nextFieldName();
            } while (strCurrentName != null);
        }
        return objCreateUsingDefault;
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
            return objCreateUsingArrayDelegate;
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
            if (zIsEnabled) {
                JsonToken jsonToken2 = JsonToken.START_ARRAY;
                if (jsonTokenNextToken == jsonToken2) {
                    JavaType valueType = getValueType(deserializationContext);
                    return deserializationContext.handleUnexpectedToken(valueType, jsonToken2, jsonParser2, "Cannot deserialize value of type %s from deeply-nested Array: only single wrapper allowed with `%s`", ClassUtil.getTypeDescription(valueType), "DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS");
                }
                Object objDeserialize = deserialize(jsonParser2, deserializationContext);
                if (jsonParser2.nextToken() != jsonToken) {
                    handleMissingEndArrayForSingle(jsonParser2, deserializationContext);
                }
                return objDeserialize;
            }
            deserializationContext2 = deserializationContext;
        } else {
            jsonParser2 = jsonParser;
            deserializationContext2 = deserializationContext;
        }
        return deserializationContext2.handleUnexpectedToken(getValueType(deserializationContext2), jsonParser2);
    }

    public final Object _deserializeOther(JsonParser jsonParser, DeserializationContext deserializationContext, JsonToken jsonToken) throws IOException {
        if (jsonToken != null) {
            switch (AnonymousClass1.$SwitchMap$com$fasterxml$jackson$core$JsonToken[jsonToken.ordinal()]) {
                case 1:
                    return deserializeFromString(jsonParser, deserializationContext);
                case 2:
                    return deserializeFromNumber(jsonParser, deserializationContext);
                case 3:
                    return deserializeFromDouble(jsonParser, deserializationContext);
                case 4:
                    return deserializeFromEmbedded(jsonParser, deserializationContext);
                case 5:
                case 6:
                    return deserializeFromBoolean(jsonParser, deserializationContext);
                case 7:
                    return deserializeFromNull(jsonParser, deserializationContext);
                case 8:
                    return _deserializeFromArray(jsonParser, deserializationContext);
                case 9:
                case 10:
                    return this._vanillaProcessing ? vanillaDeserialize(jsonParser, deserializationContext, jsonToken) : this._objectIdReader != null ? deserializeWithObjectId(jsonParser, deserializationContext) : deserializeFromObject(jsonParser, deserializationContext);
            }
        }
        return deserializationContext.handleUnexpectedToken(getValueType(deserializationContext), jsonParser);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public Object _deserializeUsingPropertyBased(JsonParser jsonParser, DeserializationContext deserializationContext) throws UnsupportedOperationException, IOException, IllegalArgumentException {
        DeserializationContext deserializationContext2;
        Object objWrapInstantiationProblem;
        PropertyBasedCreator propertyBasedCreator = this._propertyBasedCreator;
        SettableAnyProperty settableAnyProperty = this._anySetter;
        PropertyValueBuffer propertyValueBufferStartBuildingWithAnySetter = settableAnyProperty != null ? propertyBasedCreator.startBuildingWithAnySetter(jsonParser, deserializationContext, this._objectIdReader, settableAnyProperty) : propertyBasedCreator.startBuilding(jsonParser, deserializationContext, this._objectIdReader);
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        ArrayList arrayList = null;
        TokenBuffer tokenBufferBufferForInputBuffering = null;
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFindCreatorProperty = propertyBasedCreator.findCreatorProperty(strCurrentName);
            if (propertyValueBufferStartBuildingWithAnySetter.readIdProperty(strCurrentName) && settableBeanPropertyFindCreatorProperty == null) {
                deserializationContext2 = deserializationContext;
            } else if (settableBeanPropertyFindCreatorProperty != null) {
                if (activeView != null && !settableBeanPropertyFindCreatorProperty.visibleInView(activeView)) {
                    jsonParser.skipChildren();
                } else if (propertyValueBufferStartBuildingWithAnySetter.assignParameter(settableBeanPropertyFindCreatorProperty, _deserializeWithErrorWrapping(jsonParser, deserializationContext, settableBeanPropertyFindCreatorProperty))) {
                    jsonParser.nextToken();
                    try {
                        objWrapInstantiationProblem = propertyBasedCreator.build(deserializationContext, propertyValueBufferStartBuildingWithAnySetter);
                    } catch (Exception e) {
                        objWrapInstantiationProblem = wrapInstantiationProblem(e, deserializationContext);
                    }
                    Object objHandleUnknownProperties = objWrapInstantiationProblem;
                    jsonParser.assignCurrentValue(objHandleUnknownProperties);
                    if (objHandleUnknownProperties == null) {
                        _handleNullFromPropsBasedCreator(jsonParser, deserializationContext, tokenBufferBufferForInputBuffering, arrayList);
                        return null;
                    }
                    if (objHandleUnknownProperties.getClass() != this._beanType.getRawClass()) {
                        return handlePolymorphic(jsonParser, deserializationContext, jsonParser.streamReadConstraints(), objHandleUnknownProperties, tokenBufferBufferForInputBuffering);
                    }
                    DeserializationContext deserializationContext3 = deserializationContext;
                    if (tokenBufferBufferForInputBuffering != null) {
                        objHandleUnknownProperties = handleUnknownProperties(deserializationContext3, objHandleUnknownProperties, tokenBufferBufferForInputBuffering);
                    }
                    return deserialize(jsonParser, deserializationContext3, objHandleUnknownProperties);
                }
                deserializationContext2 = deserializationContext;
            } else {
                deserializationContext2 = deserializationContext;
                SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
                if (settableBeanPropertyFind != null && (!this._beanType.isRecordType() || (settableBeanPropertyFind instanceof MethodProperty))) {
                    try {
                        propertyValueBufferStartBuildingWithAnySetter.bufferProperty(settableBeanPropertyFind, _deserializeWithErrorWrapping(jsonParser, deserializationContext2, settableBeanPropertyFind));
                    } catch (UnresolvedForwardReference e2) {
                        BeanReferring beanReferringHandleUnresolvedReference = handleUnresolvedReference(deserializationContext2, settableBeanPropertyFind, propertyValueBufferStartBuildingWithAnySetter, e2);
                        if (arrayList == null) {
                            arrayList = new ArrayList();
                        }
                        arrayList.add(beanReferringHandleUnresolvedReference);
                    }
                } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                    handleIgnoredProperty(jsonParser, deserializationContext2, handledType(), strCurrentName);
                } else {
                    SettableAnyProperty settableAnyProperty2 = this._anySetter;
                    if (settableAnyProperty2 != null) {
                        try {
                            if (settableAnyProperty2.isFieldType() || this._anySetter.isSetterType()) {
                                SettableAnyProperty settableAnyProperty3 = this._anySetter;
                                propertyValueBufferStartBuildingWithAnySetter.bufferAnyProperty(settableAnyProperty3, strCurrentName, settableAnyProperty3.deserialize(jsonParser, deserializationContext2));
                            } else {
                                SettableAnyProperty settableAnyProperty4 = this._anySetter;
                                propertyValueBufferStartBuildingWithAnySetter.bufferAnyParameterProperty(settableAnyProperty4, strCurrentName, settableAnyProperty4.deserialize(jsonParser, deserializationContext2));
                            }
                        } catch (Exception e3) {
                            wrapAndThrow(e3, this._beanType.getRawClass(), strCurrentName, deserializationContext2);
                        }
                    } else if (this._ignoreAllUnknown) {
                        jsonParser.skipChildren();
                    } else {
                        if (tokenBufferBufferForInputBuffering == null) {
                            tokenBufferBufferForInputBuffering = deserializationContext2.bufferForInputBuffering(jsonParser);
                        }
                        tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                        tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParser);
                    }
                }
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
            deserializationContext = deserializationContext2;
        }
        DeserializationContext deserializationContext4 = deserializationContext;
        try {
            Object objBuild = propertyBasedCreator.build(deserializationContext4, propertyValueBufferStartBuildingWithAnySetter);
            jsonParser.assignCurrentValue(objBuild);
            if (objBuild == null) {
                _handleNullFromPropsBasedCreator(null, deserializationContext4, tokenBufferBufferForInputBuffering, arrayList);
                return null;
            }
            if (this._injectables != null) {
                injectValues(deserializationContext4, objBuild);
            }
            if (arrayList != null) {
                Iterator<BeanReferring> it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    it2.next().setBean(objBuild);
                }
            }
            return tokenBufferBufferForInputBuffering != null ? objBuild.getClass() != this._beanType.getRawClass() ? handlePolymorphic(null, deserializationContext4, jsonParser.streamReadConstraints(), objBuild, tokenBufferBufferForInputBuffering) : handleUnknownProperties(deserializationContext4, objBuild, tokenBufferBufferForInputBuffering) : objBuild;
        } catch (Exception e4) {
            return wrapInstantiationProblem(e4, deserializationContext4);
        }
    }

    public final Object _deserializeWithErrorWrapping(JsonParser jsonParser, DeserializationContext deserializationContext, SettableBeanProperty settableBeanProperty) throws IOException {
        try {
            return settableBeanProperty.deserialize(jsonParser, deserializationContext);
        } catch (Exception e) {
            return wrapAndThrow(e, this._beanType.getRawClass(), settableBeanProperty.getName(), deserializationContext);
        }
    }

    public Object _deserializeWithExternalTypeId(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj, ExternalTypeHandler externalTypeHandler) throws IOException {
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            JsonToken jsonTokenNextToken = jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind != null) {
                if (jsonTokenNextToken.isScalarValue()) {
                    externalTypeHandler.handleTypePropertyValue(jsonParser, deserializationContext, strCurrentName, obj);
                }
                if (activeView == null || settableBeanPropertyFind.visibleInView(activeView)) {
                    try {
                        settableBeanPropertyFind.deserializeAndSet(jsonParser, deserializationContext, obj);
                    } catch (Exception e) {
                        wrapAndThrow(e, obj, strCurrentName, deserializationContext);
                    }
                } else {
                    jsonParser.skipChildren();
                }
            } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                handleIgnoredProperty(jsonParser, deserializationContext, obj, strCurrentName);
            } else if (!externalTypeHandler.handlePropertyValue(jsonParser, deserializationContext, strCurrentName, obj)) {
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
        return externalTypeHandler.complete(jsonParser, deserializationContext, obj);
    }

    public void _handleNullFromPropsBasedCreator(JsonParser jsonParser, DeserializationContext deserializationContext, TokenBuffer tokenBuffer, List<BeanReferring> list) throws IOException {
        if (jsonParser != null) {
            JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
            while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
                jsonParser.nextToken();
                jsonParser.skipChildren();
                jsonTokenCurrentToken = jsonParser.nextToken();
            }
        }
        if (tokenBuffer != null) {
            handleUnknownProperties(deserializationContext, null, tokenBuffer);
        }
        if (list != null) {
            Iterator<BeanReferring> it2 = list.iterator();
            while (it2.hasNext()) {
                it2.next().setBean(null);
            }
        }
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase asArrayDeserializer() {
        return new BeanAsArrayDeserializer(this, this._beanProperties.getPropertiesInInsertionOrder());
    }

    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        if (!jsonParser.isExpectedStartObjectToken()) {
            return _deserializeOther(jsonParser, deserializationContext, jsonParser.currentToken());
        }
        if (this._vanillaProcessing) {
            return vanillaDeserialize(jsonParser, deserializationContext, jsonParser.nextToken());
        }
        jsonParser.nextToken();
        return this._objectIdReader != null ? deserializeWithObjectId(jsonParser, deserializationContext) : deserializeFromObject(jsonParser, deserializationContext);
    }

    public Object deserializeFromNull(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        if (!jsonParser.requiresCustomCodec()) {
            return deserializationContext.handleUnexpectedToken(getValueType(deserializationContext), jsonParser);
        }
        TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
        tokenBufferBufferForInputBuffering.writeEndObject();
        JsonParser jsonParserAsParser = tokenBufferBufferForInputBuffering.asParser(jsonParser);
        jsonParserAsParser.nextToken();
        Object objVanillaDeserialize = this._vanillaProcessing ? vanillaDeserialize(jsonParserAsParser, deserializationContext, JsonToken.END_OBJECT) : deserializeFromObject(jsonParserAsParser, deserializationContext);
        jsonParserAsParser.close();
        return objVanillaDeserialize;
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public Object deserializeFromObject(JsonParser jsonParser, DeserializationContext deserializationContext) throws UnsupportedOperationException, IOException, IllegalArgumentException {
        Class<?> activeView;
        ObjectIdReader objectIdReader = this._objectIdReader;
        if (objectIdReader != null && objectIdReader.maySerializeAsObject() && jsonParser.hasTokenId(5) && this._objectIdReader.isValidReferencePropertyName(jsonParser.currentName(), jsonParser)) {
            return deserializeFromObjectId(jsonParser, deserializationContext);
        }
        if (this._nonStandardCreation) {
            return this._unwrappedPropertyHandler != null ? deserializeWithUnwrapped(jsonParser, deserializationContext) : this._externalTypeIdHandler != null ? deserializeWithExternalTypeId(jsonParser, deserializationContext) : deserializeFromObjectUsingNonDefault(jsonParser, deserializationContext);
        }
        Object objCreateUsingDefault = this._valueInstantiator.createUsingDefault(deserializationContext);
        if (jsonParser.canReadObjectId()) {
            Object objectId = jsonParser.getObjectId();
            if (objectId != null) {
                _handleTypedObjectId(jsonParser, deserializationContext, objCreateUsingDefault, objectId);
            }
        } else if (this._objectIdReader != null && jsonParser.hasTokenId(2) && deserializationContext.isEnabled(DeserializationFeature.FAIL_ON_UNRESOLVED_OBJECT_IDS)) {
            deserializationContext.reportUnresolvedObjectId(this._objectIdReader, objCreateUsingDefault);
        }
        if (this._injectables != null) {
            injectValues(deserializationContext, objCreateUsingDefault);
        }
        if (this._needViewProcesing && (activeView = deserializationContext.getActiveView()) != null) {
            return deserializeWithView(jsonParser, deserializationContext, objCreateUsingDefault, activeView);
        }
        if (jsonParser.hasTokenId(5)) {
            jsonParser.assignCurrentValue(objCreateUsingDefault);
            String strCurrentName = jsonParser.currentName();
            do {
                jsonParser.nextToken();
                SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
                if (settableBeanPropertyFind != null) {
                    try {
                        settableBeanPropertyFind.deserializeAndSet(jsonParser, deserializationContext, objCreateUsingDefault);
                    } catch (Exception e) {
                        wrapAndThrow(e, objCreateUsingDefault, strCurrentName, deserializationContext);
                    }
                } else {
                    handleUnknownVanilla(jsonParser, deserializationContext, objCreateUsingDefault, strCurrentName);
                }
                strCurrentName = jsonParser.nextFieldName();
            } while (strCurrentName != null);
        }
        return objCreateUsingDefault;
    }

    public Object deserializeUsingPropertyBasedWithExternalTypeId(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        ExternalTypeHandler externalTypeHandlerStart = this._externalTypeIdHandler.start();
        PropertyBasedCreator propertyBasedCreator = this._propertyBasedCreator;
        PropertyValueBuffer propertyValueBufferStartBuilding = propertyBasedCreator.startBuilding(jsonParser, deserializationContext, this._objectIdReader);
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            JsonToken jsonTokenNextToken = jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFindCreatorProperty = propertyBasedCreator.findCreatorProperty(strCurrentName);
            if (!propertyValueBufferStartBuilding.readIdProperty(strCurrentName) || settableBeanPropertyFindCreatorProperty != null) {
                if (settableBeanPropertyFindCreatorProperty == null) {
                    SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
                    if (settableBeanPropertyFind != null) {
                        if (jsonTokenNextToken.isScalarValue()) {
                            externalTypeHandlerStart.handleTypePropertyValue(jsonParser, deserializationContext, strCurrentName, null);
                        }
                        if (activeView == null || settableBeanPropertyFind.visibleInView(activeView)) {
                            propertyValueBufferStartBuilding.bufferProperty(settableBeanPropertyFind, settableBeanPropertyFind.deserialize(jsonParser, deserializationContext));
                        } else {
                            jsonParser.skipChildren();
                        }
                    } else if (!externalTypeHandlerStart.handlePropertyValue(jsonParser, deserializationContext, strCurrentName, null)) {
                        if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                            handleIgnoredProperty(jsonParser, deserializationContext, handledType(), strCurrentName);
                        } else {
                            SettableAnyProperty settableAnyProperty = this._anySetter;
                            if (settableAnyProperty != null) {
                                propertyValueBufferStartBuilding.bufferAnyProperty(settableAnyProperty, strCurrentName, settableAnyProperty.deserialize(jsonParser, deserializationContext));
                            } else {
                                handleUnknownProperty(jsonParser, deserializationContext, this._valueClass, strCurrentName);
                            }
                        }
                    }
                } else if (!externalTypeHandlerStart.handlePropertyValue(jsonParser, deserializationContext, strCurrentName, null) && propertyValueBufferStartBuilding.assignParameter(settableBeanPropertyFindCreatorProperty, _deserializeWithErrorWrapping(jsonParser, deserializationContext, settableBeanPropertyFindCreatorProperty))) {
                    jsonParser.nextToken();
                    try {
                        Object objBuild = propertyBasedCreator.build(deserializationContext, propertyValueBufferStartBuilding);
                        if (objBuild.getClass() == this._beanType.getRawClass()) {
                            return _deserializeWithExternalTypeId(jsonParser, deserializationContext, objBuild, externalTypeHandlerStart);
                        }
                        JavaType javaType = this._beanType;
                        return deserializationContext.reportBadDefinition(javaType, String.format("Cannot create polymorphic instances with external type ids (%s -> %s)", javaType, objBuild.getClass()));
                    } catch (Exception e) {
                        wrapAndThrow(e, this._beanType.getRawClass(), strCurrentName, deserializationContext);
                    }
                }
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        try {
            return externalTypeHandlerStart.complete(jsonParser, deserializationContext, propertyValueBufferStartBuilding, propertyBasedCreator);
        } catch (Exception e2) {
            return wrapInstantiationProblem(e2, deserializationContext);
        }
    }

    public Object deserializeUsingPropertyBasedWithUnwrapped(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        Object objWrapInstantiationProblem;
        PropertyBasedCreator propertyBasedCreator = this._propertyBasedCreator;
        PropertyValueBuffer propertyValueBufferStartBuilding = propertyBasedCreator.startBuilding(jsonParser, deserializationContext, this._objectIdReader);
        TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
        tokenBufferBufferForInputBuffering.writeStartObject();
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFindCreatorProperty = propertyBasedCreator.findCreatorProperty(strCurrentName);
            if (!propertyValueBufferStartBuilding.readIdProperty(strCurrentName) || settableBeanPropertyFindCreatorProperty != null) {
                if (settableBeanPropertyFindCreatorProperty == null) {
                    SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
                    if (settableBeanPropertyFind != null) {
                        propertyValueBufferStartBuilding.bufferProperty(settableBeanPropertyFind, _deserializeWithErrorWrapping(jsonParser, deserializationContext, settableBeanPropertyFind));
                    } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                        handleIgnoredProperty(jsonParser, deserializationContext, handledType(), strCurrentName);
                    } else if (this._anySetter == null) {
                        tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                        tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParser);
                    } else {
                        TokenBuffer tokenBufferBufferAsCopyOfValue = deserializationContext.bufferAsCopyOfValue(jsonParser);
                        tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                        tokenBufferBufferForInputBuffering.append(tokenBufferBufferAsCopyOfValue);
                        try {
                            SettableAnyProperty settableAnyProperty = this._anySetter;
                            propertyValueBufferStartBuilding.bufferAnyProperty(settableAnyProperty, strCurrentName, settableAnyProperty.deserialize(tokenBufferBufferAsCopyOfValue.asParserOnFirstToken(), deserializationContext));
                        } catch (Exception e) {
                            wrapAndThrow(e, this._beanType.getRawClass(), strCurrentName, deserializationContext);
                        }
                    }
                } else if (propertyValueBufferStartBuilding.assignParameter(settableBeanPropertyFindCreatorProperty, _deserializeWithErrorWrapping(jsonParser, deserializationContext, settableBeanPropertyFindCreatorProperty))) {
                    JsonToken jsonTokenNextToken = jsonParser.nextToken();
                    try {
                        objWrapInstantiationProblem = propertyBasedCreator.build(deserializationContext, propertyValueBufferStartBuilding);
                    } catch (Exception e2) {
                        objWrapInstantiationProblem = wrapInstantiationProblem(e2, deserializationContext);
                    }
                    jsonParser.assignCurrentValue(objWrapInstantiationProblem);
                    if (objWrapInstantiationProblem == null) {
                        _handleNullFromPropsBasedCreator(jsonParser, deserializationContext, null, null);
                        return null;
                    }
                    while (jsonTokenNextToken == JsonToken.FIELD_NAME) {
                        tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParser);
                        jsonTokenNextToken = jsonParser.nextToken();
                    }
                    JsonToken jsonToken = JsonToken.END_OBJECT;
                    if (jsonTokenNextToken != jsonToken) {
                        deserializationContext.reportWrongTokenException(this, jsonToken, "Attempted to unwrap '%s' value", handledType().getName());
                    }
                    tokenBufferBufferForInputBuffering.writeEndObject();
                    return objWrapInstantiationProblem.getClass() != this._beanType.getRawClass() ? deserializationContext.reportInputMismatch(settableBeanPropertyFindCreatorProperty, "Cannot create polymorphic instances with unwrapped values", new Object[0]) : this._unwrappedPropertyHandler.processUnwrapped(jsonParser, deserializationContext, objWrapInstantiationProblem, tokenBufferBufferForInputBuffering);
                }
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        try {
            Object objBuild = propertyBasedCreator.build(deserializationContext, this._unwrappedPropertyHandler.processUnwrappedCreatorProperties(jsonParser, deserializationContext, propertyValueBufferStartBuilding, tokenBufferBufferForInputBuffering));
            if (objBuild != null) {
                return this._unwrappedPropertyHandler.processUnwrapped(jsonParser, deserializationContext, objBuild, tokenBufferBufferForInputBuffering);
            }
            _handleNullFromPropsBasedCreator(null, deserializationContext, null, null);
            return null;
        } catch (Exception e3) {
            return wrapInstantiationProblem(e3, deserializationContext);
        }
    }

    public Object deserializeWithExternalTypeId(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        if (this._propertyBasedCreator != null) {
            return deserializeUsingPropertyBasedWithExternalTypeId(jsonParser, deserializationContext);
        }
        JsonDeserializer<Object> jsonDeserializer = this._delegateDeserializer;
        return jsonDeserializer != null ? this._valueInstantiator.createUsingDelegate(deserializationContext, jsonDeserializer.deserialize(jsonParser, deserializationContext)) : deserializeWithExternalTypeId(jsonParser, deserializationContext, this._valueInstantiator.createUsingDefault(deserializationContext));
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
        jsonParser.assignCurrentValue(objCreateUsingDefault);
        if (this._injectables != null) {
            injectValues(deserializationContext, objCreateUsingDefault);
        }
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        String strCurrentName = jsonParser.hasTokenId(5) ? jsonParser.currentName() : null;
        while (strCurrentName != null) {
            jsonParser.nextToken();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            if (settableBeanPropertyFind != null) {
                if (activeView == null || settableBeanPropertyFind.visibleInView(activeView)) {
                    try {
                        settableBeanPropertyFind.deserializeAndSet(jsonParser, deserializationContext, objCreateUsingDefault);
                    } catch (Exception e) {
                        wrapAndThrow(e, objCreateUsingDefault, strCurrentName, deserializationContext);
                    }
                } else {
                    jsonParser.skipChildren();
                }
            } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                handleIgnoredProperty(jsonParser, deserializationContext, objCreateUsingDefault, strCurrentName);
            } else if (this._anySetter == null) {
                tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParser);
            } else {
                TokenBuffer tokenBufferBufferAsCopyOfValue = deserializationContext.bufferAsCopyOfValue(jsonParser);
                tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                tokenBufferBufferForInputBuffering.append(tokenBufferBufferAsCopyOfValue);
                try {
                    this._anySetter.deserializeAndSet(tokenBufferBufferAsCopyOfValue.asParserOnFirstToken(), deserializationContext, objCreateUsingDefault, strCurrentName);
                } catch (Exception e2) {
                    wrapAndThrow(e2, objCreateUsingDefault, strCurrentName, deserializationContext);
                }
            }
            strCurrentName = jsonParser.nextFieldName();
        }
        tokenBufferBufferForInputBuffering.writeEndObject();
        this._unwrappedPropertyHandler.processUnwrapped(jsonParser, deserializationContext, objCreateUsingDefault, tokenBufferBufferForInputBuffering);
        return objCreateUsingDefault;
    }

    public final Object deserializeWithView(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj, Class<?> cls) throws IOException {
        if (jsonParser.hasTokenId(5)) {
            jsonParser.assignCurrentValue(obj);
            String strCurrentName = jsonParser.currentName();
            do {
                jsonParser.nextToken();
                SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
                if (settableBeanPropertyFind == null) {
                    handleUnknownVanilla(jsonParser, deserializationContext, obj, strCurrentName);
                } else if (settableBeanPropertyFind.visibleInView(cls)) {
                    try {
                        settableBeanPropertyFind.deserializeAndSet(jsonParser, deserializationContext, obj);
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
                strCurrentName = jsonParser.nextFieldName();
            } while (strCurrentName != null);
        }
        return obj;
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase, com.fasterxml.jackson.databind.JsonDeserializer
    public JsonDeserializer<Object> unwrappingDeserializer(NameTransformer nameTransformer) {
        if (getClass() != BeanDeserializer.class || this._currentlyTransforming == nameTransformer) {
            return this;
        }
        this._currentlyTransforming = nameTransformer;
        try {
            return new BeanDeserializer(this, nameTransformer);
        } finally {
            this._currentlyTransforming = null;
        }
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase withBeanProperties(BeanPropertyMap beanPropertyMap) {
        return new BeanDeserializer(this, beanPropertyMap);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public /* bridge */ /* synthetic */ BeanDeserializerBase withByNameInclusion(Set set, Set set2) {
        return withByNameInclusion((Set<String>) set, (Set<String>) set2);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializerBase withIgnoreAllUnknown(boolean z) {
        return new BeanDeserializer(this, z);
    }

    public BeanDeserializer(BeanDeserializerBase beanDeserializerBase, boolean z) {
        super(beanDeserializerBase, z);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializer withByNameInclusion(Set<String> set, Set<String> set2) {
        return new BeanDeserializer(this, set, set2);
    }

    @Override // com.fasterxml.jackson.databind.deser.BeanDeserializerBase
    public BeanDeserializer withObjectIdReader(ObjectIdReader objectIdReader) {
        return new BeanDeserializer(this, objectIdReader);
    }

    public BeanDeserializer(BeanDeserializerBase beanDeserializerBase, NameTransformer nameTransformer) {
        super(beanDeserializerBase, nameTransformer);
    }

    public BeanDeserializer(BeanDeserializerBase beanDeserializerBase, ObjectIdReader objectIdReader) {
        super(beanDeserializerBase, objectIdReader);
    }

    public BeanDeserializer(BeanDeserializerBase beanDeserializerBase, Set<String> set, Set<String> set2) {
        super(beanDeserializerBase, set, set2);
    }

    public BeanDeserializer(BeanDeserializerBase beanDeserializerBase, BeanPropertyMap beanPropertyMap) {
        super(beanDeserializerBase, beanPropertyMap);
    }

    public Object deserializeWithExternalTypeId(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj) throws IOException {
        return _deserializeWithExternalTypeId(jsonParser, deserializationContext, obj, this._externalTypeIdHandler.start());
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x004e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // com.fasterxml.jackson.databind.JsonDeserializer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object deserialize(com.fasterxml.jackson.core.JsonParser r3, com.fasterxml.jackson.databind.DeserializationContext r4, java.lang.Object r5) throws java.lang.UnsupportedOperationException, java.io.IOException, java.lang.IllegalArgumentException {
        /*
            r2 = this;
            r3.assignCurrentValue(r5)
            com.fasterxml.jackson.databind.deser.impl.ValueInjector[] r0 = r2._injectables
            if (r0 == 0) goto La
            r2.injectValues(r4, r5)
        La:
            com.fasterxml.jackson.databind.deser.impl.UnwrappedPropertyHandler r0 = r2._unwrappedPropertyHandler
            if (r0 == 0) goto L13
            java.lang.Object r3 = r2.deserializeWithUnwrapped(r3, r4, r5)
            return r3
        L13:
            com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler r0 = r2._externalTypeIdHandler
            if (r0 == 0) goto L1c
            java.lang.Object r3 = r2.deserializeWithExternalTypeId(r3, r4, r5)
            return r3
        L1c:
            boolean r0 = r3.isExpectedStartObjectToken()
            if (r0 == 0) goto L29
            java.lang.String r0 = r3.nextFieldName()
            if (r0 != 0) goto L34
            goto L60
        L29:
            r0 = 5
            boolean r0 = r3.hasTokenId(r0)
            if (r0 == 0) goto L60
            java.lang.String r0 = r3.currentName()
        L34:
            boolean r1 = r2._needViewProcesing
            if (r1 == 0) goto L43
            java.lang.Class r1 = r4.getActiveView()
            if (r1 == 0) goto L43
            java.lang.Object r3 = r2.deserializeWithView(r3, r4, r5, r1)
            return r3
        L43:
            r3.nextToken()
            com.fasterxml.jackson.databind.deser.impl.BeanPropertyMap r1 = r2._beanProperties
            com.fasterxml.jackson.databind.deser.SettableBeanProperty r1 = r1.find(r0)
            if (r1 == 0) goto L57
            r1.deserializeAndSet(r3, r4, r5)     // Catch: java.lang.Exception -> L52
            goto L5a
        L52:
            r1 = move-exception
            r2.wrapAndThrow(r1, r5, r0, r4)
            goto L5a
        L57:
            r2.handleUnknownVanilla(r3, r4, r5, r0)
        L5a:
            java.lang.String r0 = r3.nextFieldName()
            if (r0 != 0) goto L43
        L60:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.deser.BeanDeserializer.deserialize(com.fasterxml.jackson.core.JsonParser, com.fasterxml.jackson.databind.DeserializationContext, java.lang.Object):java.lang.Object");
    }

    public Object deserializeWithUnwrapped(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj) throws IOException {
        JsonToken jsonTokenCurrentToken = jsonParser.currentToken();
        if (jsonTokenCurrentToken == JsonToken.START_OBJECT) {
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        TokenBuffer tokenBufferBufferForInputBuffering = deserializationContext.bufferForInputBuffering(jsonParser);
        tokenBufferBufferForInputBuffering.writeStartObject();
        Class<?> activeView = this._needViewProcesing ? deserializationContext.getActiveView() : null;
        while (jsonTokenCurrentToken == JsonToken.FIELD_NAME) {
            String strCurrentName = jsonParser.currentName();
            SettableBeanProperty settableBeanPropertyFind = this._beanProperties.find(strCurrentName);
            jsonParser.nextToken();
            if (settableBeanPropertyFind != null) {
                if (activeView != null && !settableBeanPropertyFind.visibleInView(activeView)) {
                    jsonParser.skipChildren();
                } else {
                    try {
                        settableBeanPropertyFind.deserializeAndSet(jsonParser, deserializationContext, obj);
                    } catch (Exception e) {
                        wrapAndThrow(e, obj, strCurrentName, deserializationContext);
                    }
                }
            } else if (IgnorePropertiesUtil.shouldIgnore(strCurrentName, this._ignorableProps, this._includableProps)) {
                handleIgnoredProperty(jsonParser, deserializationContext, obj, strCurrentName);
            } else if (this._anySetter == null) {
                tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                tokenBufferBufferForInputBuffering.copyCurrentStructure(jsonParser);
            } else {
                TokenBuffer tokenBufferBufferAsCopyOfValue = deserializationContext.bufferAsCopyOfValue(jsonParser);
                tokenBufferBufferForInputBuffering.writeFieldName(strCurrentName);
                tokenBufferBufferForInputBuffering.append(tokenBufferBufferAsCopyOfValue);
                try {
                    this._anySetter.deserializeAndSet(tokenBufferBufferAsCopyOfValue.asParserOnFirstToken(), deserializationContext, obj, strCurrentName);
                } catch (Exception e2) {
                    wrapAndThrow(e2, obj, strCurrentName, deserializationContext);
                }
            }
            jsonTokenCurrentToken = jsonParser.nextToken();
        }
        tokenBufferBufferForInputBuffering.writeEndObject();
        this._unwrappedPropertyHandler.processUnwrapped(jsonParser, deserializationContext, obj, tokenBufferBufferForInputBuffering);
        return obj;
    }
}
