package retrofit2;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Optional;

/* renamed from: retrofit2.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5177b extends AbstractC5185j {
    public final /* synthetic */ int a;

    public /* synthetic */ C5177b(int i) {
        this.a = i;
    }

    public static C5177b c() {
        return new C5177b(2);
    }

    @Override // retrofit2.AbstractC5185j
    public InterfaceC5186k a(Type type, Annotation[] annotationArr) {
        switch (this.a) {
            case 0:
                if (okhttp3.F.class.isAssignableFrom(S.i(type))) {
                    return C5176a.d;
                }
                return null;
            case 1:
            default:
                return super.a(type, annotationArr);
            case 2:
                if (type == String.class || type == Boolean.TYPE || type == Boolean.class || type == Byte.TYPE || type == Byte.class || type == Character.TYPE || type == Character.class || type == Double.TYPE || type == Double.class || type == Float.TYPE || type == Float.class || type == Integer.TYPE || type == Integer.class || type == Long.TYPE || type == Long.class || type == Short.TYPE || type == Short.class) {
                    return retrofit2.converter.scalars.a.a;
                }
                return null;
        }
    }

    @Override // retrofit2.AbstractC5185j
    public final InterfaceC5186k b(Type type, Annotation[] annotationArr, L l) {
        switch (this.a) {
            case 0:
                if (type == okhttp3.J.class) {
                    return S.m(annotationArr, retrofit2.http.w.class) ? C5176a.e : C5176a.c;
                }
                if (type == Void.class) {
                    return C5176a.g;
                }
                if (S.n(type)) {
                    return C5176a.f;
                }
                return null;
            case 1:
                if (S.i(type) != Optional.class) {
                    return null;
                }
                return new com.quizlet.login.common.interactors.d(l.d(S.h(0, (ParameterizedType) type), annotationArr), 19);
            default:
                if (type == String.class) {
                    return retrofit2.converter.scalars.b.j;
                }
                if (type == Boolean.class || type == Boolean.TYPE) {
                    return retrofit2.converter.scalars.b.b;
                }
                if (type == Byte.class || type == Byte.TYPE) {
                    return retrofit2.converter.scalars.b.c;
                }
                if (type == Character.class || type == Character.TYPE) {
                    return retrofit2.converter.scalars.b.d;
                }
                if (type == Double.class || type == Double.TYPE) {
                    return retrofit2.converter.scalars.b.e;
                }
                if (type == Float.class || type == Float.TYPE) {
                    return retrofit2.converter.scalars.b.f;
                }
                if (type == Integer.class || type == Integer.TYPE) {
                    return retrofit2.converter.scalars.b.g;
                }
                if (type == Long.class || type == Long.TYPE) {
                    return retrofit2.converter.scalars.b.h;
                }
                if (type == Short.class || type == Short.TYPE) {
                    return retrofit2.converter.scalars.b.i;
                }
                return null;
        }
    }
}
