package com.quizlet.featuregate.features.flexiblegrading;

import androidx.work.impl.model.c;
import com.quizlet.data.interactor.achievements.f;
import com.quizlet.infra.legacysyncengine.features.properties.d;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt__StringsKt;
import kotlin.u;

/* loaded from: classes2.dex */
public final class a implements h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static final boolean a(a aVar, String str) {
        aVar.getClass();
        return D.l(str, "en", true) || D.l(str, "en-US", true) || D.l(str, "en-GB", true) || D.l(str, "es", true) || D.l(str, "de", true) || D.l(str, "fr", true);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                boolean z = false;
                if (it2 == null || !it2.isEmpty()) {
                    Iterator it3 = it2.iterator();
                    while (true) {
                        if (it3.hasNext()) {
                            String input = (String) it3.next();
                            Intrinsics.checkNotNullParameter(input, "input");
                            if ((input.length() > 0 ? StringsKt__StringsKt.split$default(input, new String[]{" "}, false, 0, 6, null).size() : 0) >= 3) {
                                z = true;
                            }
                        }
                    }
                }
                return Boolean.valueOf(z);
            default:
                List it4 = (List) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                boolean z2 = false;
                if (it4 == null || !it4.isEmpty()) {
                    Iterator it5 = it4.iterator();
                    while (true) {
                        if (it5.hasNext()) {
                            String input2 = (String) it5.next();
                            Intrinsics.checkNotNullParameter(input2, "input");
                            if ((input2.length() > 0 ? StringsKt__StringsKt.split$default(input2, new String[]{" "}, false, 0, 6, null).size() : 0) >= 3) {
                                z2 = true;
                            }
                        }
                    }
                }
                return Boolean.valueOf(z2);
        }
    }

    public g b(c userProps, Object obj) {
        d contentProps = (d) obj;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(contentProps, "contentProps");
        g gVarG = contentProps.a().g(com.quizlet.infra.legacysyncengine.features.properties.c.l);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        g gVarG2 = contentProps.a().g(com.quizlet.infra.legacysyncengine.features.properties.c.c);
        Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
        p pVarP = p.p(gVarG, gVarG2, new f(this, 13));
        Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
        u uVar = contentProps.e;
        g gVarG3 = ((p) uVar.getValue()).g(com.quizlet.infra.legacysyncengine.features.properties.c.m);
        Intrinsics.checkNotNullExpressionValue(gVarG3, "map(...)");
        g gVarG4 = ((p) uVar.getValue()).g(com.quizlet.infra.legacysyncengine.features.properties.c.d);
        Intrinsics.checkNotNullExpressionValue(gVarG4, "map(...)");
        g gVarG5 = gVarG4.g(b);
        Intrinsics.checkNotNullExpressionValue(gVarG5, "map(...)");
        g gVarG6 = gVarG3.g(c);
        Intrinsics.checkNotNullExpressionValue(gVarG6, "map(...)");
        return com.google.android.gms.dynamite.d.b(pVarP, com.google.android.gms.dynamite.d.f(gVarG5, gVarG6));
    }
}
