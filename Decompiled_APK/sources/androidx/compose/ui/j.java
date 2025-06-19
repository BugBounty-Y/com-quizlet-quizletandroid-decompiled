package androidx.compose.ui;

import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class j extends kotlin.jvm.internal.r implements Function2 {
    public static final j a = new j(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        String str = (String) obj;
        o oVar = (o) obj2;
        if (str.length() == 0) {
            return oVar.toString();
        }
        return str + ", " + oVar;
    }
}
