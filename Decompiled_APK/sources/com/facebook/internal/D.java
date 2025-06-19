package com.facebook.internal;

import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.text.TextUtils;
import android.view.View;
import androidx.appcompat.app.HandlerC0048d;
import androidx.camera.camera2.internal.C0143u;
import com.facebook.login.GetTokenLoginMethodHandler;
import com.facebook.login.LoginClient;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class D implements ServiceConnection {
    public final Context a;
    public final HandlerC0048d b;
    public C0143u c;
    public boolean d;
    public Messenger e;
    public final int f;
    public final int g;
    public final String h;
    public final int i;
    public final String j;

    public D(Context context, String applicationId, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        Context applicationContext = context.getApplicationContext();
        this.a = applicationContext != null ? applicationContext : context;
        this.f = 65536;
        this.g = 65537;
        this.h = applicationId;
        this.i = 20121101;
        this.j = str;
        this.b = new HandlerC0048d(this);
    }

    public final void a(Bundle result) {
        if (this.d) {
            this.d = false;
            C0143u c0143u = this.c;
            if (c0143u != null) {
                GetTokenLoginMethodHandler this$0 = (GetTokenLoginMethodHandler) c0143u.b;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                LoginClient.Request request = (LoginClient.Request) c0143u.c;
                Intrinsics.checkNotNullParameter(request, "$request");
                this$0.getClass();
                Intrinsics.checkNotNullParameter(request, "request");
                com.facebook.login.m mVar = this$0.c;
                if (mVar != null) {
                    mVar.c = null;
                }
                this$0.c = null;
                androidx.webkit.internal.p pVar = this$0.d().e;
                if (pVar != null) {
                    View view = ((com.facebook.login.u) pVar.b).e;
                    if (view == null) {
                        Intrinsics.m("progressBar");
                        throw null;
                    }
                    view.setVisibility(8);
                }
                if (result != null) {
                    List stringArrayList = result.getStringArrayList("com.facebook.platform.extra.PERMISSIONS");
                    if (stringArrayList == null) {
                        stringArrayList = kotlin.collections.K.a;
                    }
                    Set<String> set = request.b;
                    if (set == null) {
                        set = kotlin.collections.M.a;
                    }
                    String string = result.getString("com.facebook.platform.extra.ID_TOKEN");
                    if (set.contains("openid") && (string == null || string.length() == 0)) {
                        this$0.d().l();
                        return;
                    }
                    if (stringArrayList.containsAll(set)) {
                        Intrinsics.checkNotNullParameter(request, "request");
                        Intrinsics.checkNotNullParameter(result, "result");
                        String string2 = result.getString("com.facebook.platform.extra.USER_ID");
                        if (string2 != null && string2.length() != 0) {
                            this$0.n(request, result);
                            return;
                        }
                        androidx.webkit.internal.p pVar2 = this$0.d().e;
                        if (pVar2 != null) {
                            View view2 = ((com.facebook.login.u) pVar2.b).e;
                            if (view2 == null) {
                                Intrinsics.m("progressBar");
                                throw null;
                            }
                            view2.setVisibility(0);
                        }
                        String string3 = result.getString("com.facebook.platform.extra.ACCESS_TOKEN");
                        if (string3 == null) {
                            throw new IllegalStateException("Required value was null.");
                        }
                        Intrinsics.checkNotNullExpressionValue(string3, "checkNotNull(result.getS…ocol.EXTRA_ACCESS_TOKEN))");
                        J.q(new com.facebook.login.n(result, this$0, request), string3);
                        return;
                    }
                    HashSet hashSet = new HashSet();
                    for (String str : set) {
                        if (!stringArrayList.contains(str)) {
                            hashSet.add(str);
                        }
                    }
                    if (!hashSet.isEmpty()) {
                        this$0.a("new_permissions", TextUtils.join(",", hashSet));
                    }
                    Intrinsics.checkNotNullParameter(hashSet, "<set-?>");
                    request.b = hashSet;
                }
                this$0.d().l();
            }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName name, IBinder service) throws RemoteException {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(service, "service");
        this.e = new Messenger(service);
        Bundle data = new Bundle();
        data.putString("com.facebook.platform.extra.APPLICATION_ID", this.h);
        String str = this.j;
        if (str != null) {
            data.putString("com.facebook.platform.extra.NONCE", str);
        }
        Intrinsics.checkNotNullParameter(data, "data");
        Message messageObtain = Message.obtain((Handler) null, this.f);
        messageObtain.arg1 = this.i;
        messageObtain.setData(data);
        messageObtain.replyTo = new Messenger(this.b);
        try {
            Messenger messenger = this.e;
            if (messenger != null) {
                messenger.send(messageObtain);
            }
        } catch (RemoteException unused) {
            a(null);
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.e = null;
        try {
            this.a.unbindService(this);
        } catch (IllegalArgumentException unused) {
        }
        a(null);
    }
}
