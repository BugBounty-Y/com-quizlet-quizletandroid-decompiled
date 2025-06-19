package androidx.camera.core.streamsharing;

import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.util.Rational;
import androidx.collection.C0225x;
import androidx.compose.runtime.internal.j;
import androidx.compose.ui.node.E;
import androidx.compose.ui.semantics.o;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.types.C1459f;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.button.MaterialButtonToggleGroup;
import java.util.ArrayList;
import java.util.Comparator;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.C5172u;
import org.wordpress.aztec.spans.D;

/* loaded from: classes.dex */
public final class a implements Comparator {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Rational rational = (Rational) obj2;
                Rational rational2 = (Rational) this.b;
                float fFloatValue = ((Rational) obj).floatValue();
                float fFloatValue2 = rational2.floatValue();
                float f = fFloatValue > fFloatValue2 ? fFloatValue2 / fFloatValue : fFloatValue / fFloatValue2;
                float fFloatValue3 = rational.floatValue();
                float fFloatValue4 = rational2.floatValue();
                return Float.compare(fFloatValue3 > fFloatValue4 ? fFloatValue4 / fFloatValue3 : fFloatValue3 / fFloatValue4, f);
            case 1:
                long jLongValue = ((Number) obj).longValue();
                C0225x c0225x = (C0225x) this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(c0225x.c(jLongValue)), Integer.valueOf(c0225x.c(((Number) obj2).longValue())));
            case 2:
                androidx.camera.lifecycle.f fVar = (androidx.camera.lifecycle.f) this.b;
                return kotlin.comparisons.a.b((Comparable) fVar.invoke(obj), (Comparable) fVar.invoke(obj2));
            case 3:
                int iCompare = ((Comparator) this.b).compare(obj, obj2);
                if (iCompare != 0) {
                    return iCompare;
                }
                return E.L.compare(((o) obj).c, ((o) obj2).c);
            case 4:
                int iCompare2 = ((a) this.b).compare(obj, obj2);
                return iCompare2 != 0 ? iCompare2 : kotlin.comparisons.a.b(Integer.valueOf(((o) obj).g), Integer.valueOf(((o) obj2).g));
            case 5:
                Long l = ((RevealSelfAssessmentQuestion) obj).d.a;
                ArrayList arrayList = (ArrayList) this.b;
                Intrinsics.checkNotNullParameter(arrayList, "<this>");
                Integer numValueOf = Integer.valueOf(arrayList.indexOf(l));
                Long l2 = ((RevealSelfAssessmentQuestion) obj2).d.a;
                Intrinsics.checkNotNullParameter(arrayList, "<this>");
                return kotlin.comparisons.a.b(numValueOf, Integer.valueOf(arrayList.indexOf(l2)));
            case 6:
                C1459f c1459f = (C1459f) obj;
                long j = c1459f.a;
                j jVar = (j) this.b;
                C1459f c1459f2 = (C1459f) obj2;
                return kotlin.comparisons.a.b(Integer.valueOf(jVar.f(j, c1459f.d, c1459f.c)), Integer.valueOf(jVar.f(c1459f2.a, c1459f2.d, c1459f2.c)));
            case 7:
                MaterialButton materialButton = (MaterialButton) obj;
                MaterialButton materialButton2 = (MaterialButton) obj2;
                int iCompareTo = Boolean.valueOf(materialButton.o).compareTo(Boolean.valueOf(materialButton2.o));
                if (iCompareTo != 0) {
                    return iCompareTo;
                }
                int iCompareTo2 = Boolean.valueOf(materialButton.isPressed()).compareTo(Boolean.valueOf(materialButton2.isPressed()));
                if (iCompareTo2 != 0) {
                    return iCompareTo2;
                }
                MaterialButtonToggleGroup materialButtonToggleGroup = (MaterialButtonToggleGroup) this.b;
                return Integer.valueOf(materialButtonToggleGroup.indexOfChild(materialButton)).compareTo(Integer.valueOf(materialButtonToggleGroup.indexOfChild(materialButton2)));
            case 8:
                org.wordpress.aztec.formatting.i iVar = (org.wordpress.aztec.formatting.i) this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(iVar.u().getSpanStart((D) obj)), Integer.valueOf(iVar.u().getSpanStart((D) obj2)));
            case 9:
                SpannableStringBuilder spannableStringBuilder = (SpannableStringBuilder) this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(spannableStringBuilder.getSpanStart((C5172u) obj2)), Integer.valueOf(spannableStringBuilder.getSpanStart((C5172u) obj)));
            default:
                CharSequence charSequence = (CharSequence) this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(((Spanned) charSequence).getSpanStart((C5164l) obj)), Integer.valueOf(((Spanned) charSequence).getSpanStart((C5164l) obj2)));
        }
    }

    public a(Comparator comparator) {
        this.a = 3;
        this.b = comparator;
    }
}
