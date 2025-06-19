package com.quizlet.remote.util;

import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.i;
import com.squareup.moshi.k;
import com.squareup.moshi.l;
import com.squareup.moshi.n;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements k {
    public final /* synthetic */ int a;

    @Override // com.squareup.moshi.k
    public final l a(Type type, Set annotations, D moshi) {
        Set setUnmodifiableSet;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(type, "type");
                Intrinsics.checkNotNullParameter(annotations, "annotations");
                Intrinsics.checkNotNullParameter(moshi, "moshi");
                Intrinsics.checkNotNullParameter(type, "<this>");
                Class clsD = H.d(type);
                Intrinsics.checkNotNullExpressionValue(clsD, "getRawType(this)");
                if (!clsD.isAnnotationPresent(a.class)) {
                    return null;
                }
                moshi.getClass();
                Type typeF = com.squareup.moshi.internal.b.f(com.squareup.moshi.internal.b.a(type));
                List list = moshi.a;
                int iIndexOf = list.indexOf(this);
                if (iIndexOf == -1) {
                    throw new IllegalArgumentException("Unable to skip past unknown factory " + this);
                }
                int size = list.size();
                for (int i = iIndexOf + 1; i < size; i++) {
                    l lVarA = ((k) list.get(i)).a(typeF, annotations, moshi);
                    if (lVarA != null) {
                        Intrinsics.checkNotNullExpressionValue(lVarA, "nextAdapter(...)");
                        return new i(lVarA);
                    }
                }
                throw new IllegalArgumentException("No next JsonAdapter for " + com.squareup.moshi.internal.b.i(typeF, annotations));
            default:
                Intrinsics.checkNotNullParameter(type, "type");
                Intrinsics.checkNotNullParameter(annotations, "annotations");
                Intrinsics.checkNotNullParameter(moshi, "moshi");
                if (!Intrinsics.b(type, String.class)) {
                    return null;
                }
                if (!JsonString.class.isAnnotationPresent(n.class)) {
                    throw new IllegalArgumentException(JsonString.class + " is not a JsonQualifier.");
                }
                if (annotations.isEmpty()) {
                    setUnmodifiableSet = null;
                } else {
                    Iterator it2 = annotations.iterator();
                    while (it2.hasNext()) {
                        Annotation annotation = (Annotation) it2.next();
                        if (JsonString.class.equals(annotation.annotationType())) {
                            LinkedHashSet linkedHashSet = new LinkedHashSet(annotations);
                            linkedHashSet.remove(annotation);
                            setUnmodifiableSet = Collections.unmodifiableSet(linkedHashSet);
                        }
                    }
                    setUnmodifiableSet = null;
                }
                if (setUnmodifiableSet == null) {
                    return null;
                }
                return new c(0).e();
        }
    }
}
