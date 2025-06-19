package kotlinx.serialization;

import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.collections.C4930v;
import kotlin.collections.K;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.m;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.AbstractC5044b;

/* loaded from: classes3.dex */
public final class c extends AbstractC5044b {
    public final kotlin.reflect.c a;
    public final List b;
    public final Object c;

    public c(kotlin.reflect.c baseClass) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        this.a = baseClass;
        this.b = K.a;
        this.c = l.a(m.b, new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 22));
    }

    @Override // kotlinx.serialization.internal.AbstractC5044b
    public final kotlin.reflect.c c() {
        return this.a;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @Override // kotlinx.serialization.KSerializer
    public final SerialDescriptor getDescriptor() {
        return (SerialDescriptor) this.c.getValue();
    }

    public final String toString() {
        return "kotlinx.serialization.PolymorphicSerializer(baseClass: " + this.a + ')';
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public c(C4950i baseClass, Annotation[] classAnnotations) {
        this(baseClass);
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(classAnnotations, "classAnnotations");
        this.b = C4930v.c(classAnnotations);
    }
}
