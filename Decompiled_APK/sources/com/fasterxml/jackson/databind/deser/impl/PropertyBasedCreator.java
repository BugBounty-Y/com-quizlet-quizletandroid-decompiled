package com.fasterxml.jackson.databind.deser.impl;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.deser.SettableAnyProperty;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.deser.ValueInstantiator;
import com.fasterxml.jackson.databind.util.NameTransformer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/* loaded from: classes.dex */
public final class PropertyBasedCreator {
    protected final SettableBeanProperty[] _allProperties;
    protected final int _propertyCount;
    protected final HashMap<String, SettableBeanProperty> _propertyLookup;
    protected final ValueInstantiator _valueInstantiator;

    public static class CaseInsensitiveMap extends HashMap<String, SettableBeanProperty> {
        protected final Locale _locale;

        public CaseInsensitiveMap(Locale locale) {
            this._locale = locale;
        }

        public static CaseInsensitiveMap construct(Locale locale) {
            return new CaseInsensitiveMap(locale);
        }

        @Override // java.util.HashMap, java.util.AbstractMap, java.util.Map
        public SettableBeanProperty get(Object obj) {
            return (SettableBeanProperty) super.get((Object) ((String) obj).toLowerCase(this._locale));
        }

        @Override // java.util.HashMap, java.util.AbstractMap, java.util.Map
        public SettableBeanProperty put(String str, SettableBeanProperty settableBeanProperty) {
            return (SettableBeanProperty) super.put((CaseInsensitiveMap) str.toLowerCase(this._locale), (String) settableBeanProperty);
        }
    }

    public PropertyBasedCreator(DeserializationContext deserializationContext, ValueInstantiator valueInstantiator, SettableBeanProperty[] settableBeanPropertyArr, boolean z, boolean z2) {
        this._valueInstantiator = valueInstantiator;
        if (z) {
            this._propertyLookup = CaseInsensitiveMap.construct(deserializationContext.getConfig().getLocale());
        } else {
            this._propertyLookup = new HashMap<>();
        }
        int length = settableBeanPropertyArr.length;
        this._propertyCount = length;
        this._allProperties = new SettableBeanProperty[length];
        if (z2) {
            DeserializationConfig config = deserializationContext.getConfig();
            for (SettableBeanProperty settableBeanProperty : settableBeanPropertyArr) {
                if (!settableBeanProperty.isIgnorable()) {
                    List<PropertyName> listFindAliases = settableBeanProperty.findAliases(config);
                    if (!listFindAliases.isEmpty()) {
                        Iterator<PropertyName> it2 = listFindAliases.iterator();
                        while (it2.hasNext()) {
                            this._propertyLookup.put(it2.next().getSimpleName(), settableBeanProperty);
                        }
                    }
                }
            }
        }
        for (int i = 0; i < length; i++) {
            SettableBeanProperty settableBeanProperty2 = settableBeanPropertyArr[i];
            this._allProperties[i] = settableBeanProperty2;
            if (!settableBeanProperty2.isIgnorable()) {
                this._propertyLookup.put(settableBeanProperty2.getName(), settableBeanProperty2);
            }
        }
    }

    public static PropertyBasedCreator construct(DeserializationContext deserializationContext, ValueInstantiator valueInstantiator, SettableBeanProperty[] settableBeanPropertyArr, BeanPropertyMap beanPropertyMap) throws JsonMappingException {
        int length = settableBeanPropertyArr.length;
        SettableBeanProperty[] settableBeanPropertyArr2 = new SettableBeanProperty[length];
        for (int i = 0; i < length; i++) {
            SettableBeanProperty settableBeanPropertyWithValueDeserializer = settableBeanPropertyArr[i];
            if (!settableBeanPropertyWithValueDeserializer.hasValueDeserializer() && !settableBeanPropertyWithValueDeserializer.isInjectionOnly()) {
                settableBeanPropertyWithValueDeserializer = settableBeanPropertyWithValueDeserializer.withValueDeserializer(deserializationContext.findContextualValueDeserializer(settableBeanPropertyWithValueDeserializer.getType(), settableBeanPropertyWithValueDeserializer));
            }
            settableBeanPropertyArr2[i] = settableBeanPropertyWithValueDeserializer;
        }
        return new PropertyBasedCreator(deserializationContext, valueInstantiator, settableBeanPropertyArr2, beanPropertyMap.isCaseInsensitive(), true);
    }

    public Object build(DeserializationContext deserializationContext, PropertyValueBuffer propertyValueBuffer) throws IOException {
        Object objCreateFromObjectWith = this._valueInstantiator.createFromObjectWith(deserializationContext, this._allProperties, propertyValueBuffer);
        if (objCreateFromObjectWith == null) {
            return objCreateFromObjectWith;
        }
        Object objHandleIdValue = propertyValueBuffer.handleIdValue(deserializationContext, objCreateFromObjectWith);
        for (PropertyValue propertyValueBuffered = propertyValueBuffer.buffered(); propertyValueBuffered != null; propertyValueBuffered = propertyValueBuffered.next) {
            propertyValueBuffered.assign(objHandleIdValue);
        }
        return objHandleIdValue;
    }

    public SettableBeanProperty findCreatorProperty(String str) {
        return this._propertyLookup.get(str);
    }

    public PropertyBasedCreator renameAll(NameTransformer nameTransformer) {
        if (nameTransformer == null || nameTransformer == NameTransformer.NOP) {
            return this;
        }
        int length = this._allProperties.length;
        HashMap map = new HashMap(this._propertyLookup);
        ArrayList arrayList = new ArrayList(length);
        for (SettableBeanProperty settableBeanProperty : this._allProperties) {
            if (settableBeanProperty == null) {
                arrayList.add(null);
            } else {
                SettableBeanProperty settableBeanPropertyUnwrapped = settableBeanProperty.unwrapped(nameTransformer);
                String name = settableBeanProperty.getName();
                String name2 = settableBeanPropertyUnwrapped.getName();
                arrayList.add(settableBeanPropertyUnwrapped);
                if (!name.equals(name2) && map.containsKey(name)) {
                    map.remove(name);
                    map.put(name2, settableBeanPropertyUnwrapped);
                }
            }
        }
        return new PropertyBasedCreator(this, map, (SettableBeanProperty[]) arrayList.toArray(new SettableBeanProperty[0]));
    }

    public PropertyValueBuffer startBuilding(JsonParser jsonParser, DeserializationContext deserializationContext, ObjectIdReader objectIdReader) {
        return new PropertyValueBuffer(jsonParser, deserializationContext, this._propertyCount, objectIdReader, null);
    }

    public PropertyValueBuffer startBuildingWithAnySetter(JsonParser jsonParser, DeserializationContext deserializationContext, ObjectIdReader objectIdReader, SettableAnyProperty settableAnyProperty) {
        return new PropertyValueBuffer(jsonParser, deserializationContext, this._propertyCount, objectIdReader, settableAnyProperty);
    }

    public static PropertyBasedCreator construct(DeserializationContext deserializationContext, ValueInstantiator valueInstantiator, SettableBeanProperty[] settableBeanPropertyArr, boolean z) throws JsonMappingException {
        int length = settableBeanPropertyArr.length;
        SettableBeanProperty[] settableBeanPropertyArr2 = new SettableBeanProperty[length];
        for (int i = 0; i < length; i++) {
            SettableBeanProperty settableBeanPropertyWithValueDeserializer = settableBeanPropertyArr[i];
            if (!settableBeanPropertyWithValueDeserializer.hasValueDeserializer()) {
                settableBeanPropertyWithValueDeserializer = settableBeanPropertyWithValueDeserializer.withValueDeserializer(deserializationContext.findContextualValueDeserializer(settableBeanPropertyWithValueDeserializer.getType(), settableBeanPropertyWithValueDeserializer));
            }
            settableBeanPropertyArr2[i] = settableBeanPropertyWithValueDeserializer;
        }
        return new PropertyBasedCreator(deserializationContext, valueInstantiator, settableBeanPropertyArr2, z, false);
    }

    public PropertyBasedCreator(PropertyBasedCreator propertyBasedCreator, HashMap<String, SettableBeanProperty> map, SettableBeanProperty[] settableBeanPropertyArr) {
        this._propertyCount = propertyBasedCreator._propertyCount;
        this._valueInstantiator = propertyBasedCreator._valueInstantiator;
        this._propertyLookup = map;
        this._allProperties = settableBeanPropertyArr;
    }
}
