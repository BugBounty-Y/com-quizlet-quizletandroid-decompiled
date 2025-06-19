package com.google.android.gms.internal.p000authapi;

import com.google.android.gms.common.Feature;

/* loaded from: classes2.dex */
public abstract class e {
    public static final Feature a;
    public static final Feature b;
    public static final Feature c;
    public static final Feature[] d;

    static {
        Feature feature = new Feature("auth_api_credentials_begin_sign_in", 9L);
        Feature feature2 = new Feature("auth_api_credentials_sign_out", 2L);
        a = feature2;
        Feature feature3 = new Feature("auth_api_credentials_authorize", 1L);
        Feature feature4 = new Feature("auth_api_credentials_revoke_access", 1L);
        Feature feature5 = new Feature("auth_api_credentials_save_password", 4L);
        b = feature5;
        Feature feature6 = new Feature("auth_api_credentials_get_sign_in_intent", 6L);
        c = feature6;
        d = new Feature[]{feature, feature2, feature3, feature4, feature5, feature6, new Feature("auth_api_credentials_save_account_linking_token", 3L), new Feature("auth_api_credentials_get_phone_number_hint_intent", 3L), new Feature("auth_api_credentials_verify_with_google", 1L), new Feature("auth_api_credentials_credential_provider", 1L)};
    }
}
