package com.facebook.login;

import android.os.Parcel;
import android.os.Parcelable;
import com.facebook.internal.J;
import com.facebook.login.LoginClient;
import java.util.ArrayList;
import java.util.HashMap;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.login.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1565b implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ C1565b(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel source) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(source, "source");
                return new CustomTabLoginMethodHandler(source);
            case 1:
                Intrinsics.checkNotNullParameter(source, "source");
                return new DeviceAuthMethodHandler(source);
            case 2:
                Intrinsics.checkNotNullParameter(source, "source");
                return new GetTokenLoginMethodHandler(source);
            case 3:
                Intrinsics.checkNotNullParameter(source, "source");
                return new InstagramAppLoginMethodHandler(source);
            case 4:
                Intrinsics.checkNotNullParameter(source, "source");
                return new KatanaProxyLoginMethodHandler(source);
            case 5:
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(source, "source");
                LoginClient loginClient = new LoginClient();
                loginClient.b = -1;
                Parcelable[] parcelableArray = source.readParcelableArray(LoginMethodHandler.class.getClassLoader());
                if (parcelableArray == null) {
                    parcelableArray = new Parcelable[0];
                }
                ArrayList arrayList = new ArrayList();
                int length = parcelableArray.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        loginClient.a = (LoginMethodHandler[]) arrayList.toArray(new LoginMethodHandler[0]);
                        loginClient.b = source.readInt();
                        loginClient.g = (LoginClient.Request) source.readParcelable(LoginClient.Request.class.getClassLoader());
                        HashMap mapK = J.K(source);
                        loginClient.h = mapK != null ? V.m(mapK) : null;
                        HashMap mapK2 = J.K(source);
                        loginClient.i = mapK2 != null ? V.m(mapK2) : null;
                        return loginClient;
                    }
                    Parcelable parcelable = parcelableArray[i];
                    LoginMethodHandler loginMethodHandler = parcelable instanceof LoginMethodHandler ? (LoginMethodHandler) parcelable : null;
                    if (loginMethodHandler != null) {
                        Intrinsics.checkNotNullParameter(loginClient, "<set-?>");
                        loginMethodHandler.b = loginClient;
                    }
                    if (loginMethodHandler != null) {
                        arrayList.add(loginMethodHandler);
                    }
                    i++;
                }
            default:
                Intrinsics.checkNotNullParameter(source, "source");
                return new WebViewLoginMethodHandler(source);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new CustomTabLoginMethodHandler[i];
            case 1:
                return new DeviceAuthMethodHandler[i];
            case 2:
                return new GetTokenLoginMethodHandler[i];
            case 3:
                return new InstagramAppLoginMethodHandler[i];
            case 4:
                return new KatanaProxyLoginMethodHandler[i];
            case 5:
                return new LoginClient[i];
            default:
                return new WebViewLoginMethodHandler[i];
        }
    }
}
