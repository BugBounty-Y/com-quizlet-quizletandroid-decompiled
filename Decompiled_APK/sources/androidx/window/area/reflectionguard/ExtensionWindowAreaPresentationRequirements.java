package androidx.window.area.reflectionguard;

import android.content.Context;
import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public interface ExtensionWindowAreaPresentationRequirements {
    @NonNull
    Context getPresentationContext();

    void setPresentationView(@NonNull View view);
}
