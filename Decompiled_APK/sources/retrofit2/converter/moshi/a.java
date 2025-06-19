package retrofit2.converter.moshi;

import com.squareup.moshi.D;
import com.squareup.moshi.n;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import retrofit2.AbstractC5185j;
import retrofit2.InterfaceC5186k;
import retrofit2.L;

/* loaded from: classes3.dex */
public final class a extends AbstractC5185j {
    public final D a;

    public a(D d) {
        this.a = d;
    }

    public static Set c(Annotation[] annotationArr) {
        LinkedHashSet linkedHashSet = null;
        for (Annotation annotation : annotationArr) {
            if (annotation.annotationType().isAnnotationPresent(n.class)) {
                if (linkedHashSet == null) {
                    linkedHashSet = new LinkedHashSet();
                }
                linkedHashSet.add(annotation);
            }
        }
        return linkedHashSet != null ? Collections.unmodifiableSet(linkedHashSet) : Collections.EMPTY_SET;
    }

    @Override // retrofit2.AbstractC5185j
    public final InterfaceC5186k a(Type type, Annotation[] annotationArr) {
        return new b(this.a.a(type, c(annotationArr), null));
    }

    @Override // retrofit2.AbstractC5185j
    public final InterfaceC5186k b(Type type, Annotation[] annotationArr, L l) {
        return new c(this.a.a(type, c(annotationArr), null));
    }
}
