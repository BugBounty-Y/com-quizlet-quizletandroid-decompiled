package androidx.preference;

import android.content.Context;
import android.util.AttributeSet;
import androidx.annotation.NonNull;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public final class PreferenceScreen extends PreferenceGroup {
    public PreferenceScreen(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet, androidx.core.content.res.b.b(context, R.attr.preferenceScreenStyle, android.R.attr.preferenceScreenStyle));
    }
}
