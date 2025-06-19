package assistantMode.utils;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AssistantValidationError extends IllegalArgumentException {

    @NotNull
    public static final b Companion = new b();

    public AssistantValidationError(String str) {
        super(AbstractC0147y.d("Validation error: ", str));
    }
}
