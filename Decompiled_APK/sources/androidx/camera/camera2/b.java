package androidx.camera.camera2;

import android.content.Context;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.InitializationException;
import java.util.LinkedHashSet;

/* loaded from: classes.dex */
public final /* synthetic */ class b {
    public static com.quizlet.data.repository.activitycenter.b a(Context context, Object obj, LinkedHashSet linkedHashSet) throws InitializationException {
        try {
            return new com.quizlet.data.repository.activitycenter.b(context, obj, linkedHashSet);
        } catch (CameraUnavailableException e) {
            throw new InitializationException(e);
        }
    }
}
