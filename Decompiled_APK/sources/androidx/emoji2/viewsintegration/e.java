package androidx.emoji2.viewsintegration;

import android.text.InputFilter;
import android.text.method.PasswordTransformationMethod;
import android.text.method.TransformationMethod;
import android.util.SparseArray;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7;

/* loaded from: classes.dex */
public final class e extends AbstractC3099a7 {
    public final TextView a;
    public final c b;
    public boolean c = true;

    public e(TextView textView) {
        this.a = textView;
        this.b = new c(textView);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final InputFilter[] c(InputFilter[] inputFilterArr) {
        if (!this.c) {
            SparseArray sparseArray = new SparseArray(1);
            for (int i = 0; i < inputFilterArr.length; i++) {
                InputFilter inputFilter = inputFilterArr[i];
                if (inputFilter instanceof c) {
                    sparseArray.put(i, inputFilter);
                }
            }
            if (sparseArray.size() == 0) {
                return inputFilterArr;
            }
            int length = inputFilterArr.length;
            InputFilter[] inputFilterArr2 = new InputFilter[inputFilterArr.length - sparseArray.size()];
            int i2 = 0;
            for (int i3 = 0; i3 < length; i3++) {
                if (sparseArray.indexOfKey(i3) < 0) {
                    inputFilterArr2[i2] = inputFilterArr[i3];
                    i2++;
                }
            }
            return inputFilterArr2;
        }
        int length2 = inputFilterArr.length;
        int i4 = 0;
        while (true) {
            c cVar = this.b;
            if (i4 >= length2) {
                InputFilter[] inputFilterArr3 = new InputFilter[inputFilterArr.length + 1];
                System.arraycopy(inputFilterArr, 0, inputFilterArr3, 0, length2);
                inputFilterArr3[length2] = cVar;
                return inputFilterArr3;
            }
            if (inputFilterArr[i4] == cVar) {
                return inputFilterArr;
            }
            i4++;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final boolean d() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final void e(boolean z) {
        if (z) {
            TextView textView = this.a;
            textView.setTransformationMethod(i(textView.getTransformationMethod()));
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final void f(boolean z) {
        this.c = z;
        TextView textView = this.a;
        textView.setTransformationMethod(i(textView.getTransformationMethod()));
        textView.setFilters(c(textView.getFilters()));
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3099a7
    public final TransformationMethod i(TransformationMethod transformationMethod) {
        return this.c ? ((transformationMethod instanceof h) || (transformationMethod instanceof PasswordTransformationMethod)) ? transformationMethod : new h(transformationMethod) : transformationMethod instanceof h ? ((h) transformationMethod).a : transformationMethod;
    }
}
