package com.fasterxml.jackson.databind.ser;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIncludeProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerator;
import com.fasterxml.jackson.annotation.ObjectIdGenerators$PropertyGenerator;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TokenStreamFactory;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.PropertyMetadata;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.cfg.SerializerFactoryConfig;
import com.fasterxml.jackson.databind.introspect.AnnotatedField;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.AnnotatedMethod;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.introspect.ObjectIdInfo;
import com.fasterxml.jackson.databind.jsontype.TypeResolverBuilder;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.fasterxml.jackson.databind.ser.impl.FilteredBeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.impl.MapEntryAsPOJOSerializer;
import com.fasterxml.jackson.databind.ser.impl.ObjectIdWriter;
import com.fasterxml.jackson.databind.ser.impl.PropertyBasedObjectIdGenerator;
import com.fasterxml.jackson.databind.ser.impl.UnsupportedTypeSerializer;
import com.fasterxml.jackson.databind.ser.std.MapSerializer;
import com.fasterxml.jackson.databind.ser.std.StdDelegatingSerializer;
import com.fasterxml.jackson.databind.ser.std.ToEmptyObjectSerializer;
import com.fasterxml.jackson.databind.type.ReferenceType;
import com.fasterxml.jackson.databind.util.BeanUtil;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.Converter;
import com.fasterxml.jackson.databind.util.IgnorePropertiesUtil;
import com.fasterxml.jackson.databind.util.NativeImageUtil;
import com.fasterxml.jackson.databind.util.SimpleBeanPropertyDefinition;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public class BeanSerializerFactory extends BasicSerializerFactory implements Serializable {
    public static final BeanSerializerFactory instance = new BeanSerializerFactory(null);

    public BeanSerializerFactory(SerializerFactoryConfig serializerFactoryConfig) {
        super(serializerFactoryConfig);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ boolean lambda$removeSetterlessGetters$0(BeanPropertyDefinition beanPropertyDefinition) {
        return (beanPropertyDefinition.couldDeserialize() || beanPropertyDefinition.isExplicitlyIncluded()) ? false : true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public BeanPropertyWriter _constructWriter(SerializerProvider serializerProvider, BeanPropertyDefinition beanPropertyDefinition, PropertyBuilder propertyBuilder, boolean z, AnnotatedMember annotatedMember) throws JsonMappingException {
        PropertyName fullName = beanPropertyDefinition.getFullName();
        JavaType type = annotatedMember.getType();
        BeanProperty.Std std = new BeanProperty.Std(fullName, type, beanPropertyDefinition.getWrapperName(), annotatedMember, beanPropertyDefinition.getMetadata());
        JsonSerializer<Object> jsonSerializerFindSerializerFromAnnotation = findSerializerFromAnnotation(serializerProvider, annotatedMember);
        if (jsonSerializerFindSerializerFromAnnotation instanceof ResolvableSerializer) {
            ((ResolvableSerializer) jsonSerializerFindSerializerFromAnnotation).resolve(serializerProvider);
        }
        return propertyBuilder.buildWriter(serializerProvider, beanPropertyDefinition, type, serializerProvider.handlePrimaryContextualization(jsonSerializerFindSerializerFromAnnotation, std), findPropertyTypeSerializer(type, serializerProvider.getConfig(), annotatedMember), (type.isContainerType() || type.isReferenceType()) ? findPropertyContentTypeSerializer(type, serializerProvider.getConfig(), annotatedMember) : null, annotatedMember, z);
    }

    public JsonSerializer<?> _createSerializer2(SerializerProvider serializerProvider, JavaType javaType, BeanDescription beanDescription, boolean z) throws JsonMappingException {
        JsonSerializer<?> jsonSerializerFindSerializerByAnnotations;
        SerializationConfig config = serializerProvider.getConfig();
        if (javaType.isContainerType()) {
            if (!z) {
                z = usesStaticTyping(config, beanDescription);
            }
            jsonSerializerFindSerializerByAnnotations = buildContainerSerializer(serializerProvider, javaType, beanDescription, z);
            if (jsonSerializerFindSerializerByAnnotations != null) {
                return jsonSerializerFindSerializerByAnnotations;
            }
        } else {
            if (javaType.isReferenceType()) {
                jsonSerializerFindSerializerByAnnotations = findReferenceSerializer(serializerProvider, (ReferenceType) javaType, beanDescription, z);
            } else {
                Iterator<Serializers> it2 = customSerializers().iterator();
                if (it2.hasNext()) {
                    throw a.d(it2);
                }
                jsonSerializerFindSerializerByAnnotations = null;
            }
            if (jsonSerializerFindSerializerByAnnotations == null) {
                jsonSerializerFindSerializerByAnnotations = findSerializerByAnnotations(serializerProvider, javaType, beanDescription);
            }
        }
        if (jsonSerializerFindSerializerByAnnotations == null && (jsonSerializerFindSerializerByAnnotations = findSerializerByLookup(javaType, config, beanDescription, z)) == null && (jsonSerializerFindSerializerByAnnotations = findSerializerByPrimaryType(serializerProvider, javaType, beanDescription, z)) == null && (jsonSerializerFindSerializerByAnnotations = findBeanOrAddOnSerializer(serializerProvider, javaType, beanDescription, z)) == null) {
            jsonSerializerFindSerializerByAnnotations = serializerProvider.getUnknownTypeSerializer(beanDescription.getBeanClass());
        }
        if (jsonSerializerFindSerializerByAnnotations == null || !this._factoryConfig.hasSerializerModifiers()) {
            return jsonSerializerFindSerializerByAnnotations;
        }
        Iterator<BeanSerializerModifier> it3 = this._factoryConfig.serializerModifiers().iterator();
        if (it3.hasNext()) {
            throw a.d(it3);
        }
        return jsonSerializerFindSerializerByAnnotations;
    }

    public JsonSerializer<?> _findUnsupportedTypeSerializer(SerializerProvider serializerProvider, JavaType javaType, BeanDescription beanDescription) throws JsonMappingException {
        String strCheckUnsupportedType = BeanUtil.checkUnsupportedType(serializerProvider.getConfig(), javaType);
        if (strCheckUnsupportedType == null || serializerProvider.getConfig().findMixInClassFor(javaType.getRawClass()) != null) {
            return null;
        }
        return new UnsupportedTypeSerializer(javaType, strCheckUnsupportedType);
    }

    public boolean _isUnserializableJacksonType(SerializerProvider serializerProvider, JavaType javaType) {
        Class<?> rawClass = javaType.getRawClass();
        return ObjectMapper.class.isAssignableFrom(rawClass) || ObjectReader.class.isAssignableFrom(rawClass) || ObjectWriter.class.isAssignableFrom(rawClass) || DatabindContext.class.isAssignableFrom(rawClass) || TokenStreamFactory.class.isAssignableFrom(rawClass) || JsonParser.class.isAssignableFrom(rawClass) || JsonGenerator.class.isAssignableFrom(rawClass);
    }

    public JsonSerializer<Object> constructBeanOrAddOnSerializer(SerializerProvider serializerProvider, JavaType javaType, BeanDescription beanDescription, boolean z) throws JsonMappingException {
        BeanPropertyWriter beanPropertyWriter;
        if (beanDescription.getBeanClass() == Object.class) {
            return serializerProvider.getUnknownTypeSerializer(Object.class);
        }
        JsonSerializer<?> jsonSerializer_findUnsupportedTypeSerializer = _findUnsupportedTypeSerializer(serializerProvider, javaType, beanDescription);
        if (jsonSerializer_findUnsupportedTypeSerializer != null) {
            return jsonSerializer_findUnsupportedTypeSerializer;
        }
        if (_isUnserializableJacksonType(serializerProvider, javaType)) {
            return new ToEmptyObjectSerializer(javaType);
        }
        if (javaType.isTypeOrSubTypeOf(Map.Entry.class) && ClassUtil.isJDKClass(javaType.getRawClass())) {
            return MapEntryAsPOJOSerializer.create(serializerProvider, javaType);
        }
        SerializationConfig config = serializerProvider.getConfig();
        BeanSerializerBuilder beanSerializerBuilderConstructBeanSerializerBuilder = constructBeanSerializerBuilder(beanDescription);
        beanSerializerBuilderConstructBeanSerializerBuilder.setConfig(config);
        List<BeanPropertyWriter> listFindBeanProperties = findBeanProperties(serializerProvider, beanDescription, beanSerializerBuilderConstructBeanSerializerBuilder);
        List<BeanPropertyWriter> arrayList = listFindBeanProperties == null ? new ArrayList<>() : removeOverlappingTypeIds(serializerProvider, beanDescription, beanSerializerBuilderConstructBeanSerializerBuilder, listFindBeanProperties);
        serializerProvider.getAnnotationIntrospector().findAndAddVirtualProperties(config, beanDescription.getClassInfo(), arrayList);
        if (this._factoryConfig.hasSerializerModifiers()) {
            Iterator<BeanSerializerModifier> it2 = this._factoryConfig.serializerModifiers().iterator();
            if (it2.hasNext()) {
                throw a.d(it2);
            }
        }
        List<BeanPropertyWriter> listFilterBeanProperties = filterBeanProperties(config, beanDescription, filterUnwantedJDKProperties(config, beanDescription, arrayList));
        if (this._factoryConfig.hasSerializerModifiers()) {
            Iterator<BeanSerializerModifier> it3 = this._factoryConfig.serializerModifiers().iterator();
            if (it3.hasNext()) {
                throw a.d(it3);
            }
        }
        beanSerializerBuilderConstructBeanSerializerBuilder.setObjectIdWriter(constructObjectIdHandler(serializerProvider, beanDescription, listFilterBeanProperties));
        beanSerializerBuilderConstructBeanSerializerBuilder.setProperties(listFilterBeanProperties);
        beanSerializerBuilderConstructBeanSerializerBuilder.setFilterId(findFilterId(config, beanDescription));
        AnnotatedMember annotatedMemberFindAnyGetter = beanDescription.findAnyGetter();
        if (annotatedMemberFindAnyGetter != null) {
            JavaType type = annotatedMemberFindAnyGetter.getType();
            JavaType contentType = type.getContentType();
            TypeSerializer typeSerializerCreateTypeSerializer = createTypeSerializer(config, contentType);
            JsonSerializer<Object> jsonSerializerFindSerializerFromAnnotation = findSerializerFromAnnotation(serializerProvider, annotatedMemberFindAnyGetter);
            if (jsonSerializerFindSerializerFromAnnotation == null) {
                jsonSerializerFindSerializerFromAnnotation = MapSerializer.construct(null, type, config.isEnabled(MapperFeature.USE_STATIC_TYPING), typeSerializerCreateTypeSerializer, null, null, null);
            }
            PropertyName propertyNameConstruct = PropertyName.construct(annotatedMemberFindAnyGetter.getName());
            BeanProperty.Std std = new BeanProperty.Std(propertyNameConstruct, contentType, null, annotatedMemberFindAnyGetter, PropertyMetadata.STD_OPTIONAL);
            int i = 0;
            while (true) {
                if (i >= listFilterBeanProperties.size()) {
                    beanPropertyWriter = null;
                    i = -1;
                    break;
                }
                beanPropertyWriter = listFilterBeanProperties.get(i);
                if (Objects.equals(beanPropertyWriter.getName(), annotatedMemberFindAnyGetter.getName()) || Objects.equals(beanPropertyWriter.getMember().getMember(), annotatedMemberFindAnyGetter.getMember())) {
                    break;
                }
                i++;
            }
            if (i != -1) {
                listFilterBeanProperties.set(i, new AnyGetterWriter(beanPropertyWriter, std, annotatedMemberFindAnyGetter, jsonSerializerFindSerializerFromAnnotation));
            } else {
                listFilterBeanProperties.add(new AnyGetterWriter(_constructWriter(serializerProvider, SimpleBeanPropertyDefinition.construct(config, annotatedMemberFindAnyGetter, propertyNameConstruct), new PropertyBuilder(config, beanDescription), z, annotatedMemberFindAnyGetter), std, annotatedMemberFindAnyGetter, jsonSerializerFindSerializerFromAnnotation));
            }
        }
        processViews(config, beanSerializerBuilderConstructBeanSerializerBuilder);
        if (this._factoryConfig.hasSerializerModifiers()) {
            Iterator<BeanSerializerModifier> it4 = this._factoryConfig.serializerModifiers().iterator();
            if (it4.hasNext()) {
                throw a.d(it4);
            }
        }
        try {
            JsonSerializer<?> jsonSerializerBuild = beanSerializerBuilderConstructBeanSerializerBuilder.build();
            if (jsonSerializerBuild != null) {
                return jsonSerializerBuild;
            }
            if (javaType.isRecordType() && !NativeImageUtil.needsReflectionConfiguration(javaType.getRawClass())) {
                return beanSerializerBuilderConstructBeanSerializerBuilder.createDummy();
            }
            JsonSerializer<?> jsonSerializerFindSerializerByAddonType = findSerializerByAddonType(config, javaType, beanDescription, z);
            return (jsonSerializerFindSerializerByAddonType == null && beanDescription.hasKnownClassAnnotations()) ? beanSerializerBuilderConstructBeanSerializerBuilder.createDummy() : jsonSerializerFindSerializerByAddonType;
        } catch (RuntimeException e) {
            return (JsonSerializer) serializerProvider.reportBadTypeDefinition(beanDescription, "Failed to construct BeanSerializer for %s: (%s) %s", beanDescription.getType(), e.getClass().getName(), e.getMessage());
        }
    }

    public BeanSerializerBuilder constructBeanSerializerBuilder(BeanDescription beanDescription) {
        return new BeanSerializerBuilder(beanDescription);
    }

    public BeanPropertyWriter constructFilteredBeanWriter(BeanPropertyWriter beanPropertyWriter, Class<?>[] clsArr) {
        return FilteredBeanPropertyWriter.constructViewBased(beanPropertyWriter, clsArr);
    }

    public ObjectIdWriter constructObjectIdHandler(SerializerProvider serializerProvider, BeanDescription beanDescription, List<BeanPropertyWriter> list) throws JsonMappingException {
        ObjectIdInfo objectIdInfo = beanDescription.getObjectIdInfo();
        if (objectIdInfo == null) {
            return null;
        }
        Class<? extends ObjectIdGenerator<?>> generatorType = objectIdInfo.getGeneratorType();
        if (generatorType != ObjectIdGenerators$PropertyGenerator.class) {
            return ObjectIdWriter.construct(serializerProvider.getTypeFactory().findTypeParameters(serializerProvider.constructType(generatorType), ObjectIdGenerator.class)[0], objectIdInfo.getPropertyName(), serializerProvider.objectIdGeneratorInstance(beanDescription.getClassInfo(), objectIdInfo), objectIdInfo.getAlwaysAsId());
        }
        String simpleName = objectIdInfo.getPropertyName().getSimpleName();
        int size = list.size();
        for (int i = 0; i != size; i++) {
            BeanPropertyWriter beanPropertyWriter = list.get(i);
            if (simpleName.equals(beanPropertyWriter.getName())) {
                if (i > 0) {
                    list.remove(i);
                    list.add(0, beanPropertyWriter);
                }
                return ObjectIdWriter.construct(beanPropertyWriter.getType(), null, new PropertyBasedObjectIdGenerator(objectIdInfo, beanPropertyWriter), objectIdInfo.getAlwaysAsId());
            }
        }
        throw new IllegalArgumentException(a.m("Invalid Object Id definition for ", ClassUtil.getTypeDescription(beanDescription.getType()), ": cannot find property with name ", ClassUtil.name(simpleName)));
    }

    public PropertyBuilder constructPropertyBuilder(SerializationConfig serializationConfig, BeanDescription beanDescription) {
        return new PropertyBuilder(serializationConfig, beanDescription);
    }

    @Override // com.fasterxml.jackson.databind.ser.SerializerFactory
    public JsonSerializer<Object> createSerializer(SerializerProvider serializerProvider, JavaType javaType) throws JsonMappingException {
        JavaType javaTypeRefineSerializationType;
        SerializationConfig config = serializerProvider.getConfig();
        BeanDescription beanDescriptionIntrospect = config.introspect(javaType);
        JsonSerializer<?> jsonSerializerFindSerializerFromAnnotation = findSerializerFromAnnotation(serializerProvider, beanDescriptionIntrospect.getClassInfo());
        if (jsonSerializerFindSerializerFromAnnotation != null) {
            return jsonSerializerFindSerializerFromAnnotation;
        }
        AnnotationIntrospector annotationIntrospector = config.getAnnotationIntrospector();
        boolean z = false;
        if (annotationIntrospector == null) {
            javaTypeRefineSerializationType = javaType;
        } else {
            try {
                javaTypeRefineSerializationType = annotationIntrospector.refineSerializationType(config, beanDescriptionIntrospect.getClassInfo(), javaType);
            } catch (JsonMappingException e) {
                return (JsonSerializer) serializerProvider.reportBadTypeDefinition(beanDescriptionIntrospect, e.getMessage(), new Object[0]);
            }
        }
        if (javaTypeRefineSerializationType != javaType) {
            if (!javaTypeRefineSerializationType.hasRawClass(javaType.getRawClass())) {
                beanDescriptionIntrospect = config.introspect(javaTypeRefineSerializationType);
            }
            z = true;
        }
        Converter<Object, Object> converterFindSerializationConverter = beanDescriptionIntrospect.findSerializationConverter();
        if (converterFindSerializationConverter == null) {
            return _createSerializer2(serializerProvider, javaTypeRefineSerializationType, beanDescriptionIntrospect, z);
        }
        JavaType outputType = converterFindSerializationConverter.getOutputType(serializerProvider.getTypeFactory());
        if (!outputType.hasRawClass(javaTypeRefineSerializationType.getRawClass())) {
            beanDescriptionIntrospect = config.introspect(outputType);
            jsonSerializerFindSerializerFromAnnotation = findSerializerFromAnnotation(serializerProvider, beanDescriptionIntrospect.getClassInfo());
        }
        if (jsonSerializerFindSerializerFromAnnotation == null && !outputType.isJavaLangObject()) {
            jsonSerializerFindSerializerFromAnnotation = _createSerializer2(serializerProvider, outputType, beanDescriptionIntrospect, true);
        }
        return new StdDelegatingSerializer(converterFindSerializationConverter, outputType, jsonSerializerFindSerializerFromAnnotation);
    }

    @Override // com.fasterxml.jackson.databind.ser.BasicSerializerFactory
    public Iterable<Serializers> customSerializers() {
        return this._factoryConfig.serializers();
    }

    public List<BeanPropertyWriter> filterBeanProperties(SerializationConfig serializationConfig, BeanDescription beanDescription, List<BeanPropertyWriter> list) {
        JsonIgnoreProperties.Value defaultPropertyIgnorals = serializationConfig.getDefaultPropertyIgnorals(beanDescription.getBeanClass(), beanDescription.getClassInfo());
        Set<String> setFindIgnoredForSerialization = defaultPropertyIgnorals != null ? defaultPropertyIgnorals.findIgnoredForSerialization() : null;
        JsonIncludeProperties.Value defaultPropertyInclusions = serializationConfig.getDefaultPropertyInclusions(beanDescription.getBeanClass(), beanDescription.getClassInfo());
        Set<String> included = defaultPropertyInclusions != null ? defaultPropertyInclusions.getIncluded() : null;
        if (included != null || (setFindIgnoredForSerialization != null && !setFindIgnoredForSerialization.isEmpty())) {
            Iterator<BeanPropertyWriter> it2 = list.iterator();
            while (it2.hasNext()) {
                if (IgnorePropertiesUtil.shouldIgnore(it2.next().getName(), setFindIgnoredForSerialization, included)) {
                    it2.remove();
                }
            }
        }
        return list;
    }

    public List<BeanPropertyWriter> filterUnwantedJDKProperties(SerializationConfig serializationConfig, BeanDescription beanDescription, List<BeanPropertyWriter> list) {
        if (beanDescription.getType().isTypeOrSubTypeOf(CharSequence.class) && list.size() == 1) {
            AnnotatedMember member = list.get(0).getMember();
            if ((member instanceof AnnotatedMethod) && "isEmpty".equals(member.getName()) && member.getDeclaringClass() == CharSequence.class) {
                list.remove(0);
            }
        }
        return list;
    }

    public JsonSerializer<Object> findBeanOrAddOnSerializer(SerializerProvider serializerProvider, JavaType javaType, BeanDescription beanDescription, boolean z) throws JsonMappingException {
        if (isPotentialBeanType(javaType.getRawClass()) || ClassUtil.isEnumType(javaType.getRawClass())) {
            return constructBeanOrAddOnSerializer(serializerProvider, javaType, beanDescription, z);
        }
        return null;
    }

    public List<BeanPropertyWriter> findBeanProperties(SerializerProvider serializerProvider, BeanDescription beanDescription, BeanSerializerBuilder beanSerializerBuilder) throws JsonMappingException {
        SerializerProvider serializerProvider2;
        List<BeanPropertyDefinition> listFindProperties = beanDescription.findProperties();
        SerializationConfig config = serializerProvider.getConfig();
        removeIgnorableTypes(config, beanDescription, listFindProperties);
        if (config.isEnabled(MapperFeature.REQUIRE_SETTERS_FOR_GETTERS)) {
            removeSetterlessGetters(config, beanDescription, listFindProperties);
        }
        if (listFindProperties.isEmpty()) {
            return null;
        }
        boolean zUsesStaticTyping = usesStaticTyping(config, beanDescription);
        PropertyBuilder propertyBuilderConstructPropertyBuilder = constructPropertyBuilder(config, beanDescription);
        ArrayList arrayList = new ArrayList(listFindProperties.size());
        for (BeanPropertyDefinition beanPropertyDefinition : listFindProperties) {
            AnnotatedMember accessor = beanPropertyDefinition.getAccessor();
            if (!beanPropertyDefinition.isTypeId()) {
                AnnotationIntrospector.ReferenceProperty referencePropertyFindReferenceType = beanPropertyDefinition.findReferenceType();
                if (referencePropertyFindReferenceType == null || !referencePropertyFindReferenceType.isBackReference()) {
                    if (accessor instanceof AnnotatedMethod) {
                        serializerProvider2 = serializerProvider;
                        arrayList.add(_constructWriter(serializerProvider2, beanPropertyDefinition, propertyBuilderConstructPropertyBuilder, zUsesStaticTyping, (AnnotatedMethod) accessor));
                    } else {
                        serializerProvider2 = serializerProvider;
                        arrayList.add(_constructWriter(serializerProvider2, beanPropertyDefinition, propertyBuilderConstructPropertyBuilder, zUsesStaticTyping, (AnnotatedField) accessor));
                    }
                    serializerProvider = serializerProvider2;
                }
            } else if (accessor != null) {
                beanSerializerBuilder.setTypeId(accessor);
            }
        }
        return arrayList;
    }

    public TypeSerializer findPropertyContentTypeSerializer(JavaType javaType, SerializationConfig serializationConfig, AnnotatedMember annotatedMember) throws JsonMappingException {
        JavaType contentType = javaType.getContentType();
        TypeResolverBuilder<?> typeResolverBuilderFindPropertyContentTypeResolver = serializationConfig.getAnnotationIntrospector().findPropertyContentTypeResolver(serializationConfig, annotatedMember, javaType);
        return typeResolverBuilderFindPropertyContentTypeResolver == null ? createTypeSerializer(serializationConfig, contentType) : typeResolverBuilderFindPropertyContentTypeResolver.buildTypeSerializer(serializationConfig, contentType, serializationConfig.getSubtypeResolver().collectAndResolveSubtypesByClass(serializationConfig, annotatedMember, contentType));
    }

    public TypeSerializer findPropertyTypeSerializer(JavaType javaType, SerializationConfig serializationConfig, AnnotatedMember annotatedMember) throws JsonMappingException {
        TypeResolverBuilder<?> typeResolverBuilderFindPropertyTypeResolver = serializationConfig.getAnnotationIntrospector().findPropertyTypeResolver(serializationConfig, annotatedMember, javaType);
        return typeResolverBuilderFindPropertyTypeResolver == null ? createTypeSerializer(serializationConfig, javaType) : typeResolverBuilderFindPropertyTypeResolver.buildTypeSerializer(serializationConfig, javaType, serializationConfig.getSubtypeResolver().collectAndResolveSubtypesByClass(serializationConfig, annotatedMember, javaType));
    }

    public boolean isPotentialBeanType(Class<?> cls) {
        return ClassUtil.canBeABeanType(cls) == null && !ClassUtil.isProxyType(cls);
    }

    public void processViews(SerializationConfig serializationConfig, BeanSerializerBuilder beanSerializerBuilder) {
        List<BeanPropertyWriter> properties = beanSerializerBuilder.getProperties();
        boolean zIsEnabled = serializationConfig.isEnabled(MapperFeature.DEFAULT_VIEW_INCLUSION);
        int size = properties.size();
        BeanPropertyWriter[] beanPropertyWriterArr = new BeanPropertyWriter[size];
        int i = 0;
        for (int i2 = 0; i2 < size; i2++) {
            BeanPropertyWriter beanPropertyWriter = properties.get(i2);
            Class<?>[] views = beanPropertyWriter.getViews();
            if (views != null && views.length != 0) {
                i++;
                beanPropertyWriterArr[i2] = constructFilteredBeanWriter(beanPropertyWriter, views);
            } else if (zIsEnabled) {
                beanPropertyWriterArr[i2] = beanPropertyWriter;
            }
        }
        if (zIsEnabled && i == 0) {
            return;
        }
        beanSerializerBuilder.setFilteredProperties(beanPropertyWriterArr);
    }

    public void removeIgnorableTypes(SerializationConfig serializationConfig, BeanDescription beanDescription, List<BeanPropertyDefinition> list) {
        AnnotationIntrospector annotationIntrospector = serializationConfig.getAnnotationIntrospector();
        HashMap map = new HashMap();
        Iterator<BeanPropertyDefinition> it2 = list.iterator();
        while (it2.hasNext()) {
            BeanPropertyDefinition next = it2.next();
            if (next.getAccessor() == null) {
                it2.remove();
            } else {
                Class<?> rawPrimaryType = next.getRawPrimaryType();
                Boolean isIgnoredType = (Boolean) map.get(rawPrimaryType);
                if (isIgnoredType == null) {
                    isIgnoredType = serializationConfig.getConfigOverride(rawPrimaryType).getIsIgnoredType();
                    if (isIgnoredType == null && (isIgnoredType = annotationIntrospector.isIgnorableType(serializationConfig.introspectClassAnnotations(rawPrimaryType).getClassInfo())) == null) {
                        isIgnoredType = Boolean.FALSE;
                    }
                    map.put(rawPrimaryType, isIgnoredType);
                }
                if (isIgnoredType.booleanValue()) {
                    it2.remove();
                }
            }
        }
    }

    public List<BeanPropertyWriter> removeOverlappingTypeIds(SerializerProvider serializerProvider, BeanDescription beanDescription, BeanSerializerBuilder beanSerializerBuilder, List<BeanPropertyWriter> list) {
        int size = list.size();
        for (int i = 0; i < size; i++) {
            BeanPropertyWriter beanPropertyWriter = list.get(i);
            TypeSerializer typeSerializer = beanPropertyWriter.getTypeSerializer();
            if (typeSerializer != null && typeSerializer.getTypeInclusion() == JsonTypeInfo.As.EXTERNAL_PROPERTY) {
                PropertyName propertyNameConstruct = PropertyName.construct(typeSerializer.getPropertyName());
                Iterator<BeanPropertyWriter> it2 = list.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        break;
                    }
                    BeanPropertyWriter next = it2.next();
                    if (next != beanPropertyWriter && next.wouldConflictWithName(propertyNameConstruct)) {
                        beanPropertyWriter.assignTypeSerializer(null);
                        break;
                    }
                }
            }
        }
        return list;
    }

    public void removeSetterlessGetters(SerializationConfig serializationConfig, BeanDescription beanDescription, List<BeanPropertyDefinition> list) {
        list.removeIf(new com.fasterxml.jackson.databind.deser.std.a(1));
    }
}
