package com.onetrust.otpublishers.headless.Public;

import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;

/* loaded from: classes2.dex */
public interface OTCallback {
    void onFailure(@NonNull OTResponse oTResponse);

    void onSuccess(@NonNull OTResponse oTResponse);
}
