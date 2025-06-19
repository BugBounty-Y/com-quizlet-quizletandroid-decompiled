package org.wordpress.aztec.watchers;

import android.text.Editable;
import android.text.TextWatcher;
import com.google.firebase.crashlytics.internal.metadata.q;
import java.lang.ref.WeakReference;
import java.util.concurrent.ConcurrentLinkedQueue;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.spans.AbstractC5167o;

/* loaded from: classes3.dex */
public final class a implements TextWatcher {
    public final WeakReference a;
    public boolean b;
    public boolean c;
    public final ConcurrentLinkedQueue d;

    public a(AztecText aztecText) {
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.a = new WeakReference(aztecText);
        this.d = new ConcurrentLinkedQueue();
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) {
        Intrinsics.checkNotNullParameter(text, "text");
        if (this.b) {
            AztecText aztecText = (AztecText) this.a.get();
            if (aztecText == null || (!aztecText.i1.isEmpty() && System.currentTimeMillis() - ((org.wordpress.aztec.watchers.event.text.e) CollectionsKt.U(aztecText.i1)).d < 100)) {
                this.c = true;
            }
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        AztecText aztecText;
        Editable text2;
        AbstractC5167o[] abstractC5167oArr;
        Intrinsics.checkNotNullParameter(text, "text");
        WeakReference weakReference = this.a;
        AztecText aztecText2 = (AztecText) weakReference.get();
        if (aztecText2 == null || aztecText2.m || (aztecText = (AztecText) weakReference.get()) == null || aztecText.q || i2 <= 0) {
            return;
        }
        this.b = true;
        AztecText aztecText3 = (AztecText) weakReference.get();
        if (aztecText3 != null && (text2 = aztecText3.getText()) != null && (abstractC5167oArr = (AbstractC5167o[]) text2.getSpans(i, i2 + i, AbstractC5167o.class)) != null) {
            for (AbstractC5167o abstractC5167o : abstractC5167oArr) {
                this.d.add(abstractC5167o);
                if (!this.c && abstractC5167o.f.get() != null) {
                    throw new ClassCastException();
                }
            }
        }
        AztecText aztecText4 = (AztecText) weakReference.get();
        if (aztecText4 != null) {
            aztecText4.postDelayed(new q(this, 27), 500L);
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(text, "text");
    }
}
