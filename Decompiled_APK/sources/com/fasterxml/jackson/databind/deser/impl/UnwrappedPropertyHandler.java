package com.fasterxml.jackson.databind.deser.impl;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.PropertyName;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;
import com.fasterxml.jackson.databind.util.NameTransformer;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/* loaded from: classes.dex */
public class UnwrappedPropertyHandler {
    protected final List<SettableBeanProperty> _creatorProperties;
    protected final List<SettableBeanProperty> _properties;

    public UnwrappedPropertyHandler() {
        this._creatorProperties = new ArrayList();
        this._properties = new ArrayList();
    }

    public static PropertyName creatorParamName(int i) {
        return new PropertyName(a.f(i, "@JsonUnwrapped/"));
    }

    private List<SettableBeanProperty> renameProperties(Collection<SettableBeanProperty> collection, NameTransformer nameTransformer) {
        ArrayList arrayList = new ArrayList(collection.size());
        for (SettableBeanProperty settableBeanProperty : collection) {
            if (settableBeanProperty == null) {
                arrayList.add(null);
            } else {
                arrayList.add(settableBeanProperty.unwrapped(nameTransformer));
            }
        }
        return arrayList;
    }

    public void addCreatorProperty(SettableBeanProperty settableBeanProperty) {
        this._creatorProperties.add(settableBeanProperty);
    }

    public void addProperty(SettableBeanProperty settableBeanProperty) {
        this._properties.add(settableBeanProperty);
    }

    public Object processUnwrapped(JsonParser jsonParser, DeserializationContext deserializationContext, Object obj, TokenBuffer tokenBuffer) throws IOException {
        for (SettableBeanProperty settableBeanProperty : this._properties) {
            JsonParser jsonParserAsParser = tokenBuffer.asParser(jsonParser.streamReadConstraints());
            jsonParserAsParser.nextToken();
            settableBeanProperty.deserializeAndSet(jsonParserAsParser, deserializationContext, obj);
        }
        return obj;
    }

    public PropertyValueBuffer processUnwrappedCreatorProperties(JsonParser jsonParser, DeserializationContext deserializationContext, PropertyValueBuffer propertyValueBuffer, TokenBuffer tokenBuffer) throws IOException {
        for (SettableBeanProperty settableBeanProperty : this._creatorProperties) {
            JsonParser jsonParserAsParser = tokenBuffer.asParser(jsonParser.streamReadConstraints());
            jsonParserAsParser.nextToken();
            propertyValueBuffer.assignParameter(settableBeanProperty, settableBeanProperty.deserialize(jsonParserAsParser, deserializationContext));
        }
        return propertyValueBuffer;
    }

    public UnwrappedPropertyHandler renameAll(NameTransformer nameTransformer) {
        return new UnwrappedPropertyHandler(renameProperties(this._creatorProperties, nameTransformer), renameProperties(this._properties, nameTransformer));
    }

    public UnwrappedPropertyHandler(List<SettableBeanProperty> list, List<SettableBeanProperty> list2) {
        this._creatorProperties = list;
        this._properties = list2;
    }
}
