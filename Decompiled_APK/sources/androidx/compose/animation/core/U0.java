package androidx.compose.animation.core;

import android.view.View;
import androidx.compose.runtime.InterfaceC0790d;
import androidx.core.view.InterfaceC1062t;
import java.lang.reflect.Array;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class U0 implements P0, androidx.compose.ui.text.input.s, InterfaceC0790d, InterfaceC1062t {
    public final /* synthetic */ int a;
    public final int b;
    public int c;
    public final Object d;

    public /* synthetic */ U0(Object obj, int i, int i2, int i3) {
        this.a = i3;
        this.d = obj;
        this.b = i;
        this.c = i2;
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void c(int i, Object obj) {
        ((InterfaceC0790d) this.d).c(i + (this.c == 0 ? this.b : 0), obj);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void d(Object obj) {
        this.c++;
        ((InterfaceC0790d) this.d).d(obj);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void e(int i, int i2, int i3) {
        int i4 = this.c == 0 ? this.b : 0;
        ((InterfaceC0790d) this.d).e(i + i4, i2 + i4, i3);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void f(int i, int i2) {
        ((InterfaceC0790d) this.d).f(i + (this.c == 0 ? this.b : 0), i2);
    }

    @Override // androidx.compose.ui.text.input.s
    public int g(int i) {
        int iG = ((androidx.compose.ui.text.input.s) this.d).g(i);
        if (i >= 0 && i <= this.c) {
            androidx.compose.foundation.text.R0.c(iG, this.b, i);
        }
        return iG;
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void h() {
        if (!(this.c > 0)) {
            androidx.compose.runtime.r.c("OffsetApplier up called with no corresponding down");
        }
        this.c--;
        ((InterfaceC0790d) this.d).h();
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public void i(int i, Object obj) {
        ((InterfaceC0790d) this.d).i(i + (this.c == 0 ? this.b : 0), obj);
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((com.quizlet.data.interactor.progress.c) this.d).j(j, abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    @Override // androidx.compose.runtime.InterfaceC0790d
    public Object l() {
        return ((InterfaceC0790d) this.d).l();
    }

    @Override // androidx.compose.animation.core.P0
    public int m() {
        return this.c;
    }

    public byte o(int i, int i2) {
        return ((byte[][]) this.d)[i2][i];
    }

    @Override // androidx.compose.ui.text.input.s
    public int p(int i) {
        int iP = ((androidx.compose.ui.text.input.s) this.d).p(i);
        if (i >= 0 && i <= this.b) {
            androidx.compose.foundation.text.R0.b(iP, this.c, i);
        }
        return iP;
    }

    public void q(int i, int i2, int i3) {
        ((byte[][]) this.d)[i2][i] = (byte) i3;
    }

    public void r(int i, int i2, boolean z) {
        ((byte[][]) this.d)[i2][i] = z ? (byte) 1 : (byte) 0;
    }

    @Override // androidx.compose.animation.core.N0
    public AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return ((com.quizlet.data.interactor.progress.c) this.d).t(j, abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    public String toString() {
        switch (this.a) {
            case 6:
                int i = this.b;
                int i2 = this.c;
                StringBuilder sb = new StringBuilder((i * 2 * i2) + 2);
                for (int i3 = 0; i3 < i2; i3++) {
                    byte[] bArr = ((byte[][]) this.d)[i3];
                    for (int i4 = 0; i4 < i; i4++) {
                        byte b = bArr[i4];
                        if (b == 0) {
                            sb.append(" 0");
                        } else if (b != 1) {
                            sb.append("  ");
                        } else {
                            sb.append(" 1");
                        }
                    }
                    sb.append('\n');
                }
                return sb.toString();
            default:
                return super.toString();
        }
    }

    @Override // androidx.compose.animation.core.P0
    public int u() {
        return this.b;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public androidx.core.view.D0 w(androidx.core.view.D0 d0, View view) {
        int i = d0.a.g(519).b;
        View view2 = (View) this.d;
        int i2 = this.b;
        if (i2 >= 0) {
            view2.getLayoutParams().height = i2 + i;
            view2.setLayoutParams(view2.getLayoutParams());
        }
        view2.setPadding(view2.getPaddingLeft(), this.c + i, view2.getPaddingRight(), view2.getPaddingBottom());
        return d0;
    }

    public U0(int i, int i2, int i3) {
        this.a = i3;
        switch (i3) {
            case 7:
                this.d = null;
                this.b = i;
                int i4 = i2 & 7;
                this.c = i4 == 0 ? 8 : i4;
                break;
            default:
                this.d = (byte[][]) Array.newInstance((Class<?>) Byte.TYPE, i2, i);
                this.b = i;
                this.c = i2;
                break;
        }
    }

    public U0() {
        this.a = 7;
        this.d = new U0[256];
        this.b = 0;
        this.c = 0;
    }

    public U0(InterfaceC0790d interfaceC0790d, int i) {
        this.a = 3;
        this.d = interfaceC0790d;
        this.b = i;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public U0(int i, int i2, Function0 function0) {
        this.a = 1;
        this.b = i;
        this.c = i2;
        this.d = (kotlin.jvm.internal.r) function0;
    }

    public U0(View view, int i, int i2) {
        this.a = 5;
        this.b = i;
        this.d = view;
        this.c = i2;
    }

    public U0(int i, int i2, B b) {
        this.a = 0;
        this.b = i;
        this.c = i2;
        this.d = new com.quizlet.data.interactor.progress.c(new H(i, i2, b));
    }
}
