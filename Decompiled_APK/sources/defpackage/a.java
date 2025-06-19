package defpackage;

import java.util.Map;
import kotlin.collections.V;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.D;
import kotlin.text.I;
import kotlin.text.MatchResult;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import kotlin.text.m;

/* loaded from: classes.dex */
public final class a extends r implements Function1 {
    public static final a a = new a(1);

    /* JADX WARN: Type inference failed for: r2v7, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r6v1, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws NumberFormatException {
        MatchResult it2 = (MatchResult) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        Regex regex = b.a;
        String value = it2.getValue();
        int i = Integer.parseInt(I.D(1, value));
        String strP = D.p(D.p(I.C(value.length() - 1, value), 'v', (char) 252), 'V', (char) 220);
        for (Map.Entry entry : b.e.entrySet()) {
            String str = (String) entry.getKey();
            String str2 = (String) entry.getValue();
            if (StringsKt.G(strP, str, false)) {
                m mVarB = b.b.b(str2);
                Intrinsics.d(mVarB);
                String value2 = mVarB.getValue();
                return D.o(D.o(strP, str, str2, false), value2, ((String[]) V.d(Integer.valueOf(i), b.d))[((Number) V.d(value2, b.c)).intValue()], false);
            }
        }
        return value;
    }
}
