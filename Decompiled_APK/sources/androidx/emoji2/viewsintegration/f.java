package androidx.emoji2.viewsintegration;

import android.text.InputFilter;
import android.text.method.TransformationMethod;
import android.widget.TextView;
import androidx.emoji2.text.j;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7;

/* loaded from: classes.dex */
public final class f extends AbstractC3099a7 {
    public final e a;

    public f(TextView textView) {
        this.a = new e(textView);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final InputFilter[] c(InputFilter[] inputFilterArr) {
        return !j.c() ? inputFilterArr : this.a.c(inputFilterArr);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final boolean d() {
        return this.a.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final void e(boolean z) {
        if (j.c()) {
            this.a.e(z);
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final void f(boolean z) {
        boolean zC = j.c();
        e eVar = this.a;
        if (zC) {
            eVar.f(z);
        } else {
            eVar.c = z;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final TransformationMethod i(TransformationMethod transformationMethod) {
        return !j.c() ? transformationMethod : this.a.i(transformationMethod);
    }
}
