package androidx.compose.ui.text.android;

import android.graphics.Paint;
import android.graphics.Rect;
import android.text.Layout;
import android.text.TextPaint;
import com.google.android.gms.ads.internal.client.C1608n;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class x {
    public final TextPaint a;
    public final boolean b;
    public final boolean c;
    public androidx.compose.ui.text.android.selection.f d;
    public final Layout e;
    public final int f;
    public final int g;
    public final int h;
    public final float i;
    public final float j;
    public final boolean k;
    public final Paint.FontMetricsInt l;
    public final int m;
    public final androidx.compose.ui.text.android.style.h[] n;
    public final Rect o = new Rect();
    public C1608n p;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x01fc  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x022d  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x025b A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:127:0x027b  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x02e6  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x02f5  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0137 A[PHI: r11
  0x0137: PHI (r11v7 int) = (r11v6 int), (r11v9 int) binds: [B:67:0x0149, B:60:0x0130] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0151  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01af  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public x(java.lang.CharSequence r32, float r33, android.text.TextPaint r34, int r35, android.text.TextUtils.TruncateAt r36, int r37, boolean r38, int r39, int r40, int r41, int r42, int r43, int r44, androidx.compose.ui.text.android.m r45) {
        /*
            Method dump skipped, instructions count: 791
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.android.x.<init>(java.lang.CharSequence, float, android.text.TextPaint, int, android.text.TextUtils$TruncateAt, int, boolean, int, int, int, int, int, int, androidx.compose.ui.text.android.m):void");
    }

    public final int a() {
        boolean z = this.c;
        Layout layout = this.e;
        return (z ? layout.getLineBottom(this.f - 1) : layout.getHeight()) + this.g + this.h + this.m;
    }

    public final float b(int i) {
        return i == this.f + (-1) ? this.i + this.j : DefinitionKt.NO_Float_VALUE;
    }

    public final C1608n c() {
        C1608n c1608n = this.p;
        if (c1608n != null) {
            return c1608n;
        }
        Layout layout = this.e;
        C1608n c1608n2 = new C1608n();
        c1608n2.a = layout;
        ArrayList arrayList = new ArrayList();
        int length = 0;
        do {
            int iL = StringsKt.L(((Layout) c1608n2.a).getText(), '\n', length, false, 4);
            length = iL < 0 ? ((Layout) c1608n2.a).getText().length() : iL + 1;
            arrayList.add(Integer.valueOf(length));
        } while (length < ((Layout) c1608n2.a).getText().length());
        c1608n2.b = arrayList;
        int size = arrayList.size();
        ArrayList arrayList2 = new ArrayList(size);
        for (int i = 0; i < size; i++) {
            arrayList2.add(null);
        }
        c1608n2.c = arrayList2;
        c1608n2.d = new boolean[((ArrayList) c1608n2.b).size()];
        ((ArrayList) c1608n2.b).size();
        this.p = c1608n2;
        return c1608n2;
    }

    public final float d(int i) {
        Paint.FontMetricsInt fontMetricsInt;
        return this.g + ((i != this.f + (-1) || (fontMetricsInt = this.l) == null) ? this.e.getLineBaseline(i) : g(i) - fontMetricsInt.ascent);
    }

    public final float e(int i) {
        Paint.FontMetricsInt fontMetricsInt;
        int i2 = this.f;
        int i3 = i2 - 1;
        Layout layout = this.e;
        if (i != i3 || (fontMetricsInt = this.l) == null) {
            return this.g + layout.getLineBottom(i) + (i == i2 + (-1) ? this.h : 0);
        }
        return layout.getLineBottom(i - 1) + fontMetricsInt.bottom;
    }

    public final int f(int i) {
        Layout layout = this.e;
        return layout.getEllipsisStart(i) == 0 ? layout.getLineEnd(i) : layout.getText().length();
    }

    public final float g(int i) {
        return this.e.getLineTop(i) + (i == 0 ? 0 : this.g);
    }

    public final float h(int i, boolean z) {
        return b(this.e.getLineForOffset(i)) + c().m(i, true, z);
    }

    public final float i(int i, boolean z) {
        return b(this.e.getLineForOffset(i)) + c().m(i, false, z);
    }

    public final androidx.compose.ui.text.android.selection.f j() {
        androidx.compose.ui.text.android.selection.f fVar = this.d;
        if (fVar != null) {
            return fVar;
        }
        Layout layout = this.e;
        androidx.compose.ui.text.android.selection.f fVar2 = new androidx.compose.ui.text.android.selection.f(layout.getText(), layout.getText().length(), this.a.getTextLocale());
        this.d = fVar2;
        return fVar2;
    }
}
