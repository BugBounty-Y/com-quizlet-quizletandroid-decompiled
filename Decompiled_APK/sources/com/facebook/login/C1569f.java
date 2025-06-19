package com.facebook.login;

import com.facebook.FacebookException;
import com.facebook.FacebookRequestError;
import com.facebook.login.DeviceAuthDialog;
import com.facebook.login.LoginClient;
import java.util.Arrays;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.facebook.login.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1569f implements com.facebook.q {
    public final /* synthetic */ int a;
    public final /* synthetic */ DeviceAuthDialog b;

    public /* synthetic */ C1569f(DeviceAuthDialog deviceAuthDialog, int i) {
        this.a = i;
        this.b = deviceAuthDialog;
    }

    @Override // com.facebook.q
    public final void a(com.facebook.w response) throws JSONException {
        switch (this.a) {
            case 0:
                DeviceAuthDialog this$0 = this.b;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(response, "response");
                if (!this$0.y) {
                    FacebookRequestError facebookRequestError = response.c;
                    if (facebookRequestError != null) {
                        FacebookException facebookException = facebookRequestError.i;
                        if (facebookException == null) {
                            facebookException = new FacebookException();
                        }
                        this$0.S(facebookException);
                        break;
                    } else {
                        JSONObject jSONObject = response.b;
                        if (jSONObject == null) {
                            jSONObject = new JSONObject();
                        }
                        DeviceAuthDialog.RequestState requestState = new DeviceAuthDialog.RequestState();
                        try {
                            String string = jSONObject.getString("user_code");
                            requestState.b = string;
                            String str = String.format(Locale.ENGLISH, "https://facebook.com/device?user_code=%1$s&qr=1", Arrays.copyOf(new Object[]{string}, 1));
                            Intrinsics.checkNotNullExpressionValue(str, "format(locale, format, *args)");
                            requestState.a = str;
                            requestState.c = jSONObject.getString("code");
                            requestState.d = jSONObject.getLong("interval");
                            this$0.W(requestState);
                            break;
                        } catch (JSONException e) {
                            this$0.S(new FacebookException(e));
                            return;
                        }
                    }
                }
                break;
            default:
                DeviceAuthDialog this$02 = this.b;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                Intrinsics.checkNotNullParameter(response, "response");
                if (!this$02.u.get()) {
                    FacebookRequestError facebookRequestError2 = response.c;
                    if (facebookRequestError2 != null) {
                        int i = facebookRequestError2.c;
                        if (i != 1349174 && i != 1349172) {
                            if (i != 1349152) {
                                if (i != 1349173) {
                                    FacebookException facebookException2 = facebookRequestError2.i;
                                    if (facebookException2 == null) {
                                        facebookException2 = new FacebookException();
                                    }
                                    this$02.S(facebookException2);
                                    break;
                                } else {
                                    this$02.R();
                                    break;
                                }
                            } else {
                                DeviceAuthDialog.RequestState requestState2 = this$02.x;
                                if (requestState2 != null) {
                                    com.facebook.devicerequests.internal.b.a(requestState2.b);
                                }
                                LoginClient.Request request = this$02.A;
                                if (request == null) {
                                    this$02.R();
                                    break;
                                } else {
                                    this$02.X(request);
                                    break;
                                }
                            }
                        } else {
                            this$02.V();
                            break;
                        }
                    } else {
                        try {
                            JSONObject jSONObject2 = response.b;
                            if (jSONObject2 == null) {
                                jSONObject2 = new JSONObject();
                            }
                            String string2 = jSONObject2.getString("access_token");
                            Intrinsics.checkNotNullExpressionValue(string2, "resultObject.getString(\"access_token\")");
                            this$02.T(string2, jSONObject2.getLong("expires_in"), Long.valueOf(jSONObject2.optLong("data_access_expiration_time")));
                            break;
                        } catch (JSONException e2) {
                            this$02.S(new FacebookException(e2));
                        }
                    }
                }
                break;
        }
    }
}
