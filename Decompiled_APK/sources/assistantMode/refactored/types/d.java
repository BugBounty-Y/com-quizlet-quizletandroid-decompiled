package assistantMode.refactored.types;

import assistantMode.enums.k;
import assistantMode.types.QuestionMetadata;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
/* loaded from: classes.dex */
public interface d extends e {

    @NotNull
    public static final Question$Companion Companion = Question$Companion.a;

    k a();

    @Override // assistantMode.refactored.types.g
    QuestionMetadata getMetadata();
}
