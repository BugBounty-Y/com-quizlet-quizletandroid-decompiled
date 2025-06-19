package grading.impls;

import com.google.android.gms.internal.mlkit_vision_camera.k3;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.text.Normalizer;
import java.util.Locale;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.Regex;

/* loaded from: classes3.dex */
public final class c extends r implements Function1 {
    public static final c b = new c(1, 0);
    public static final c c = new c(1, 1);
    public static final c d = new c(1, 2);
    public static final c e = new c(1, 3);
    public static final c f = new c(1, 4);
    public static final c g = new c(1, 5);
    public static final c h = new c(1, 6);
    public static final c i = new c(1, 7);
    public static final c j = new c(1, 8);
    public static final c k = new c(1, 9);
    public static final c l = new c(1, 10);
    public static final c m = new c(1, 11);
    public static final c n = new c(1, 12);
    public static final c o = new c(1, 13);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String strReplace;
        switch (this.a) {
            case 0:
                String lambdaToTransform = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform, "$this$lambdaToTransform");
                Intrinsics.checkNotNullParameter(lambdaToTransform, "<this>");
                String strNormalize = Normalizer.normalize(lambdaToTransform, Normalizer.Form.NFC);
                Intrinsics.checkNotNullExpressionValue(strNormalize, "normalize(...)");
                return strNormalize;
            case 1:
                String $receiver = (String) obj;
                Intrinsics.checkNotNullParameter($receiver, "$this$$receiver");
                return grading.core.g.i.replace($receiver, " ");
            case 2:
                String $receiver2 = (String) obj;
                Intrinsics.checkNotNullParameter($receiver2, "$this$$receiver");
                return grading.core.g.n.replace($receiver2, "ss");
            case 3:
                String input = (String) obj;
                Intrinsics.checkNotNullParameter(input, "$this$lambdaToTransform");
                Regex regex = defpackage.b.a;
                Intrinsics.checkNotNullParameter(input, "input");
                return defpackage.b.a.f(input, defpackage.a.a);
            case 4:
                String lambdaToTransform2 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform2, "$this$lambdaToTransform");
                String lowerCase = lambdaToTransform2.toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                return lowerCase;
            case 5:
                String lambdaToTransform3 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform3, "$this$lambdaToTransform");
                return grading.core.g.h.replace(lambdaToTransform3, "and");
            case 6:
                String lambdaToTransform4 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform4, "$this$lambdaToTransform");
                Object obj2 = util.b.a;
                Intrinsics.checkNotNullParameter(lambdaToTransform4, "<this>");
                return grading.core.g.r.replace(grading.core.g.q.replace(grading.core.g.p.replace(grading.core.g.o.replace(grading.core.g.a.replace(lambdaToTransform4, " "), "-"), "-"), SimpleComparison.EQUAL_TO_OPERATION), SimpleComparison.EQUAL_TO_OPERATION);
            case 7:
                String lambdaToTransform5 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform5, "$this$lambdaToTransform");
                return grading.core.g.a.replace(lambdaToTransform5, "");
            case 8:
                String lambdaToTransform6 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform6, "$this$lambdaToTransform");
                return grading.core.g.e.replace(lambdaToTransform6, " ");
            case 9:
                String lambdaToTransform7 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform7, "$this$lambdaToTransform");
                return grading.core.g.f.replace(lambdaToTransform7, "");
            case 10:
                String lambdaToTransform8 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform8, "$this$lambdaToTransform");
                return k3.g(lambdaToTransform8);
            case 11:
                String lambdaToTransform9 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform9, "$this$lambdaToTransform");
                Object obj3 = util.b.a;
                Intrinsics.checkNotNullParameter(lambdaToTransform9, "<this>");
                return grading.core.g.b.replace(lambdaToTransform9, "");
            case 12:
                String lambdaToTransform10 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform10, "$this$lambdaToTransform");
                return grading.core.g.u.replace(grading.core.g.t.replace(lambdaToTransform10, ""), "");
            default:
                String lambdaToTransform11 = (String) obj;
                Intrinsics.checkNotNullParameter(lambdaToTransform11, "$this$lambdaToTransform");
                Object obj4 = util.b.a;
                return (lambdaToTransform11 == null || (strReplace = grading.core.g.d.replace(lambdaToTransform11, "")) == null) ? "" : strReplace;
        }
    }
}
