package androidx.compose.foundation;

import android.graphics.Matrix;
import android.graphics.Path;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.text.C0982b;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class O0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O0(int i, androidx.compose.ui.layout.W w, int i2) {
        super(1);
        this.a = 3;
        this.c = i;
        this.b = w;
        this.d = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V.g((androidx.compose.ui.layout.V) obj, (androidx.compose.ui.layout.W) this.b, this.c, this.d);
                return Unit.a;
            case 1:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, (androidx.compose.ui.layout.W) this.b, this.c, this.d);
                return Unit.a;
            case 2:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, (androidx.compose.ui.layout.W) this.b, -this.c, -this.d);
                return Unit.a;
            case 3:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, (androidx.compose.ui.layout.W) this.b, kotlin.math.c.b((this.c - r0.a) / 2.0f), kotlin.math.c.b((this.d - r0.b) / 2.0f));
                return Unit.a;
            default:
                androidx.compose.ui.text.q qVar = (androidx.compose.ui.text.q) obj;
                C0982b c0982b = qVar.a;
                int iB = qVar.b(this.c);
                int iB2 = qVar.b(this.d);
                CharSequence charSequence = c0982b.e;
                if (iB < 0 || iB > iB2 || iB2 > charSequence.length()) {
                    StringBuilder sbW = android.support.v4.media.session.a.w("start(", iB, ") or end(", ") is out of range [0..", iB2);
                    sbW.append(charSequence.length());
                    sbW.append("], or start > end!");
                    throw new IllegalArgumentException(sbW.toString().toString());
                }
                Path path = new Path();
                androidx.compose.ui.text.android.x xVar = c0982b.d;
                xVar.e.getSelectionPath(iB, iB2, path);
                int i = xVar.g;
                if (i != 0 && !path.isEmpty()) {
                    path.offset(DefinitionKt.NO_Float_VALUE, i);
                }
                long jC = Q4.c(DefinitionKt.NO_Float_VALUE, qVar.f);
                Matrix matrix = new Matrix();
                matrix.setTranslate(androidx.compose.ui.geometry.b.d(jC), androidx.compose.ui.geometry.b.e(jC));
                path.transform(matrix);
                ((C0850j) this.b).a.addPath(path, androidx.compose.ui.geometry.b.d(0L), androidx.compose.ui.geometry.b.e(0L));
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ O0(Object obj, int i, int i2, int i3) {
        super(1);
        this.a = i3;
        this.b = obj;
        this.c = i;
        this.d = i2;
    }
}
