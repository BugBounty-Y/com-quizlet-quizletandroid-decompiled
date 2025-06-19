package androidx.compose.ui.text.platform;

import android.text.Layout;
import android.text.TextPaint;
import androidx.camera.camera2.internal.a0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.text.L;
import androidx.compose.ui.text.android.m;
import androidx.compose.ui.text.s;
import androidx.compose.ui.text.y;
import com.skydoves.balloon.internals.DefinitionKt;
import java.text.BreakIterator;
import java.util.Iterator;
import java.util.List;
import java.util.PriorityQueue;
import kotlin.Pair;

/* loaded from: classes.dex */
public final class c implements s {
    public final String a;
    public final L b;
    public final List c;
    public final List d;
    public final androidx.compose.ui.text.font.i e;
    public final androidx.compose.ui.unit.b f;
    public final d g;
    public final CharSequence h;
    public final m i;
    public io.ktor.client.plugins.api.d j;
    public final boolean k;
    public final int l;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:11:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x0362  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x0414  */
    /* JADX WARN: Removed duplicated region for block: B:247:0x04b4  */
    /* JADX WARN: Removed duplicated region for block: B:269:0x04ef  */
    /* JADX WARN: Removed duplicated region for block: B:272:0x0529  */
    /* JADX WARN: Removed duplicated region for block: B:279:0x055e  */
    /* JADX WARN: Removed duplicated region for block: B:311:0x0622  */
    /* JADX WARN: Removed duplicated region for block: B:371:0x0769  */
    /* JADX WARN: Removed duplicated region for block: B:394:0x07d4  */
    /* JADX WARN: Type inference failed for: r1v0, types: [androidx.compose.ui.text.platform.c, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v11, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r4v5 */
    /* JADX WARN: Type inference failed for: r4v6, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r8v7, types: [android.text.Spannable] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public c(java.lang.String r40, androidx.compose.ui.text.L r41, java.util.List r42, java.util.List r43, androidx.compose.ui.text.font.i r44, androidx.compose.ui.unit.b r45) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 2236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.platform.c.<init>(java.lang.String, androidx.compose.ui.text.L, java.util.List, java.util.List, androidx.compose.ui.text.font.i, androidx.compose.ui.unit.b):void");
    }

    @Override // androidx.compose.ui.text.s
    public final boolean a() {
        io.ktor.client.plugins.api.d dVar = this.j;
        if (dVar != null ? dVar.s() : false) {
            return true;
        }
        if (!this.k) {
            y yVar = this.b.c;
            androidx.appcompat.app.L l = h.a;
            androidx.appcompat.app.L l2 = h.a;
            W0 w0K = (W0) l2.b;
            if (w0K == null) {
                if (androidx.emoji2.text.j.c()) {
                    w0K = l2.K();
                    l2.b = w0K;
                } else {
                    w0K = i.a;
                }
            }
            if (((Boolean) w0K.getValue()).booleanValue()) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.compose.ui.text.s
    public final float b() {
        m mVar = this.i;
        if (!Float.isNaN(mVar.e)) {
            return mVar.e;
        }
        TextPaint textPaint = mVar.b;
        BreakIterator lineInstance = BreakIterator.getLineInstance(textPaint.getTextLocale());
        CharSequence charSequence = mVar.a;
        lineInstance.setText(new androidx.compose.ui.text.android.j(charSequence.length(), charSequence));
        PriorityQueue priorityQueue = new PriorityQueue(10, new a0(5));
        int i = 0;
        for (int next = lineInstance.next(); next != -1; next = lineInstance.next()) {
            if (priorityQueue.size() < 10) {
                priorityQueue.add(new Pair(Integer.valueOf(i), Integer.valueOf(next)));
            } else {
                Pair pair = (Pair) priorityQueue.peek();
                if (pair != null && ((Number) pair.b).intValue() - ((Number) pair.a).intValue() < next - i) {
                    priorityQueue.poll();
                    priorityQueue.add(new Pair(Integer.valueOf(i), Integer.valueOf(next)));
                }
            }
            i = next;
        }
        Iterator it2 = priorityQueue.iterator();
        float fMax = DefinitionKt.NO_Float_VALUE;
        while (it2.hasNext()) {
            Pair pair2 = (Pair) it2.next();
            fMax = Math.max(fMax, Layout.getDesiredWidth(charSequence, ((Number) pair2.a).intValue(), ((Number) pair2.b).intValue(), textPaint));
        }
        mVar.e = fMax;
        return fMax;
    }

    @Override // androidx.compose.ui.text.s
    public final float d() {
        return this.i.b();
    }
}
