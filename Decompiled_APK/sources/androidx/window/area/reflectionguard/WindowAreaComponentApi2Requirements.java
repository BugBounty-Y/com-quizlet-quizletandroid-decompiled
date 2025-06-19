package androidx.window.area.reflectionguard;

import android.app.Activity;
import androidx.annotation.NonNull;
import androidx.window.extensions.core.util.function.Consumer;

/* loaded from: classes.dex */
public interface WindowAreaComponentApi2Requirements {
    void addRearDisplayStatusListener(@NonNull Consumer<Integer> consumer);

    void endRearDisplaySession();

    void removeRearDisplayStatusListener(@NonNull Consumer<Integer> consumer);

    void startRearDisplaySession(@NonNull Activity activity, @NonNull Consumer<Integer> consumer);
}
