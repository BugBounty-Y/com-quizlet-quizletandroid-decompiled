package com.facebook.login;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.fragment.app.I;
import com.facebook.login.LoginClient;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class DeviceAuthMethodHandler extends LoginMethodHandler {
    public static ScheduledThreadPoolExecutor e;
    public final String c;
    public static final A d = new A();

    @NotNull
    public static final Parcelable.Creator<DeviceAuthMethodHandler> CREATOR = new C1565b(1);

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DeviceAuthMethodHandler(LoginClient loginClient) {
        super(loginClient);
        Intrinsics.checkNotNullParameter(loginClient, "loginClient");
        this.c = "device_auth";
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final String f() {
        return this.c;
    }

    @Override // com.facebook.login.LoginMethodHandler
    public final int m(LoginClient.Request request) {
        Intrinsics.checkNotNullParameter(request, "request");
        I iF = d().f();
        if (iF == null || iF.isFinishing()) {
            return 1;
        }
        DeviceAuthDialog deviceAuthDialog = new DeviceAuthDialog();
        deviceAuthDialog.O(iF.getSupportFragmentManager(), "login_with_facebook");
        deviceAuthDialog.X(request);
        return 1;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DeviceAuthMethodHandler(Parcel parcel) {
        super(parcel);
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        this.c = "device_auth";
    }
}
