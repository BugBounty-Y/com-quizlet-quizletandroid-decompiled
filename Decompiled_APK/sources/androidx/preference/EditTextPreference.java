package androidx.preference;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.annotation.NonNull;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public class EditTextPreference extends DialogPreference {
    /* JADX WARN: Illegal instructions before constructor call */
    public EditTextPreference(@NonNull Context context, AttributeSet attributeSet) {
        int iB = androidx.core.content.res.b.b(context, R.attr.editTextPreferenceStyle, android.R.attr.editTextPreferenceStyle);
        super(context, attributeSet, iB);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, b.c, iB, 0);
        if (typedArrayObtainStyledAttributes.getBoolean(0, typedArrayObtainStyledAttributes.getBoolean(0, false))) {
            if (com.quizlet.shared.usecase.folderstudymaterials.b.b == null) {
                com.quizlet.shared.usecase.folderstudymaterials.b.b = new com.quizlet.shared.usecase.folderstudymaterials.b(4);
            }
            this.g = com.quizlet.shared.usecase.folderstudymaterials.b.b;
        }
        typedArrayObtainStyledAttributes.recycle();
    }

    @Override // androidx.preference.Preference
    public final Object c(TypedArray typedArray, int i) {
        return typedArray.getString(i);
    }

    public EditTextPreference(@NonNull Context context) {
        this(context, null);
    }
}
