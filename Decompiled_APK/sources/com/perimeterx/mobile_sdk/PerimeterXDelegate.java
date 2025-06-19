package com.perimeterx.mobile_sdk;

import androidx.annotation.Keep;
import java.util.HashMap;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public interface PerimeterXDelegate {
    void perimeterxChallengeCancelledHandler(@NotNull String str);

    void perimeterxChallengeRenderFailedHandler(@NotNull String str);

    void perimeterxChallengeRenderedHandler(@NotNull String str);

    void perimeterxChallengeSolvedHandler(@NotNull String str);

    void perimeterxHeadersWereUpdated(@NotNull HashMap<String, String> map, @NotNull String str);

    void perimeterxRequestBlockedHandler(String str, @NotNull String str2);
}
