package com.fasterxml.jackson.databind.deser.std;

import com.fasterxml.jackson.databind.introspect.AnnotatedAndMetadata;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.ser.BeanSerializerFactory;
import com.quizlet.db.data.models.persisted.DBStudySetting;
import java.util.Objects;
import java.util.function.Predicate;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Predicate {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // java.util.function.Predicate
    public final boolean test(Object obj) {
        switch (this.a) {
            case 0:
                return StdKeyDeserializers.lambda$findStringBasedKeyDeserializer$0((AnnotatedAndMetadata) obj);
            case 1:
                return BeanSerializerFactory.lambda$removeSetterlessGetters$0((BeanPropertyDefinition) obj);
            default:
                return Objects.nonNull((DBStudySetting) obj);
        }
    }
}
