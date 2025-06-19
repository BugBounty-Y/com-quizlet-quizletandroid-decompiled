package androidx.compose.ui.text.platform;

import android.text.TextPaint;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.text.o;
import androidx.compose.ui.text.q;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public abstract class i {
    public static final j a = new j(false);

    public static final void a(o oVar, InterfaceC0858s interfaceC0858s, AbstractC0857q abstractC0857q, float f, U u, androidx.compose.ui.text.style.j jVar, androidx.compose.ui.graphics.drawscope.e eVar) {
        ArrayList arrayList = oVar.h;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            q qVar = (q) arrayList.get(i);
            qVar.a.g(interfaceC0858s, abstractC0857q, f, u, jVar, eVar);
            interfaceC0858s.p(DefinitionKt.NO_Float_VALUE, qVar.a.b());
        }
    }

    public static final void b(TextPaint textPaint, float f) {
        if (Float.isNaN(f)) {
            return;
        }
        if (f < DefinitionKt.NO_Float_VALUE) {
            f = 0.0f;
        }
        if (f > 1.0f) {
            f = 1.0f;
        }
        textPaint.setAlpha(Math.round(f * 255));
    }
}
