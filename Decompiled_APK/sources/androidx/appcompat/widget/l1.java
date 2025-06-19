package androidx.appcompat.widget;

import android.widget.EditText;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final class l1 extends androidx.emoji2.text.h {
    public final /* synthetic */ int a = 1;
    public final WeakReference b;

    public l1(EditText editText) {
        this.b = new WeakReference(editText);
    }

    @Override // androidx.emoji2.text.h
    public void a() {
        switch (this.a) {
            case 0:
                SwitchCompat switchCompat = (SwitchCompat) this.b.get();
                if (switchCompat != null) {
                    switchCompat.c();
                    break;
                }
                break;
        }
    }

    @Override // androidx.emoji2.text.h
    public final void b() {
        switch (this.a) {
            case 0:
                SwitchCompat switchCompat = (SwitchCompat) this.b.get();
                if (switchCompat != null) {
                    switchCompat.c();
                    break;
                }
                break;
            default:
                androidx.emoji2.viewsintegration.g.a((EditText) this.b.get(), 1);
                break;
        }
    }

    public l1(SwitchCompat switchCompat) {
        this.b = new WeakReference(switchCompat);
    }
}
