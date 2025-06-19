package retrofit2;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.concurrent.CompletableFuture;

/* renamed from: retrofit2.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5184i extends AbstractC5180e {
    public final /* synthetic */ int a;

    public /* synthetic */ C5184i(int i) {
        this.a = i;
    }

    @Override // retrofit2.AbstractC5180e
    public final InterfaceC5181f a(Type type, Annotation[] annotationArr, L l) {
        InterfaceC5181f bVar;
        Type typeH;
        boolean z;
        boolean z2;
        switch (this.a) {
            case 0:
                if (S.i(type) != CompletableFuture.class) {
                    return null;
                }
                if (!(type instanceof ParameterizedType)) {
                    throw new IllegalStateException("CompletableFuture return type must be parameterized as CompletableFuture<Foo> or CompletableFuture<? extends Foo>");
                }
                Type typeH2 = S.h(0, (ParameterizedType) type);
                if (S.i(typeH2) != K.class) {
                    bVar = new com.quizlet.quizletandroid.k(typeH2, 20);
                } else {
                    if (!(typeH2 instanceof ParameterizedType)) {
                        throw new IllegalStateException("Response must be parameterized as Response<Foo> or Response<? extends Foo>");
                    }
                    bVar = new com.quizlet.local.ormlite.models.term.b(S.h(0, (ParameterizedType) typeH2), 21);
                }
                return bVar;
            default:
                Class clsI = S.i(type);
                if (clsI == io.reactivex.rxjava3.core.a.class) {
                    return new retrofit2.adapter.rxjava3.e(Void.class, false, true, false, false, false, true);
                }
                boolean z3 = clsI == io.reactivex.rxjava3.core.e.class;
                boolean z4 = clsI == io.reactivex.rxjava3.core.p.class;
                boolean z5 = clsI == io.reactivex.rxjava3.core.g.class;
                if (clsI != io.reactivex.rxjava3.core.i.class && !z3 && !z4 && !z5) {
                    return null;
                }
                if (!(type instanceof ParameterizedType)) {
                    String str = !z3 ? !z4 ? z5 ? "Maybe" : "Observable" : "Single" : "Flowable";
                    throw new IllegalStateException(str + " return type must be parameterized as " + str + "<Foo> or " + str + "<? extends Foo>");
                }
                Type typeH3 = S.h(0, (ParameterizedType) type);
                Class clsI2 = S.i(typeH3);
                if (clsI2 == K.class) {
                    if (!(typeH3 instanceof ParameterizedType)) {
                        throw new IllegalStateException("Response must be parameterized as Response<Foo> or Response<? extends Foo>");
                    }
                    typeH = S.h(0, (ParameterizedType) typeH3);
                    z2 = false;
                    z = false;
                } else if (clsI2 != retrofit2.adapter.rxjava3.d.class) {
                    typeH = typeH3;
                    z = true;
                    z2 = false;
                } else {
                    if (!(typeH3 instanceof ParameterizedType)) {
                        throw new IllegalStateException("Result must be parameterized as Result<Foo> or Result<? extends Foo>");
                    }
                    typeH = S.h(0, (ParameterizedType) typeH3);
                    z2 = true;
                    z = false;
                }
                return new retrofit2.adapter.rxjava3.e(typeH, z2, z, z3, z4, z5, false);
        }
    }
}
