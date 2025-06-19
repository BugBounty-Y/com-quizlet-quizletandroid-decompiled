package com.facebook.login;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.Html;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import androidx.compose.animation.d0;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import androidx.fragment.app.I;
import com.amazon.device.ads.DtbDeviceData;
import com.facebook.AccessToken;
import com.facebook.FacebookActivity;
import com.facebook.FacebookException;
import com.facebook.FacebookRequestError;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.J;
import com.facebook.login.DeviceAuthDialog;
import com.facebook.login.LoginClient;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public class DeviceAuthDialog extends DialogInterfaceOnCancelListenerC1151t {
    public LoginClient.Request A;
    public View q;
    public TextView r;
    public TextView s;
    public DeviceAuthMethodHandler t;
    public final AtomicBoolean u = new AtomicBoolean();
    public volatile com.facebook.u v;
    public volatile ScheduledFuture w;
    public volatile RequestState x;
    public boolean y;
    public boolean z;

    @Metadata
    public static final class RequestState implements Parcelable {

        @NotNull
        public static final Parcelable.Creator<RequestState> CREATOR = new k();
        public String a;
        public String b;
        public String c;
        public long d;
        public long e;

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            dest.writeString(this.b);
            dest.writeString(this.c);
            dest.writeLong(this.d);
            dest.writeLong(this.e);
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        l lVar = new l(this, requireActivity());
        lVar.setContentView(Q(com.facebook.devicerequests.internal.b.b() && !this.z));
        return lVar;
    }

    public final void P(String userId, com.quizlet.data.repository.folderset.c cVar, String accessToken, Date date, Date date2) {
        DeviceAuthMethodHandler deviceAuthMethodHandler = this.t;
        if (deviceAuthMethodHandler != null) {
            String applicationId = com.facebook.o.b();
            ArrayList arrayList = (ArrayList) cVar.b;
            com.facebook.g gVar = com.facebook.g.DEVICE_AUTH;
            Intrinsics.checkNotNullParameter(accessToken, "accessToken");
            Intrinsics.checkNotNullParameter(applicationId, "applicationId");
            Intrinsics.checkNotNullParameter(userId, "userId");
            AccessToken token = new AccessToken(accessToken, applicationId, userId, arrayList, (ArrayList) cVar.c, (ArrayList) cVar.d, gVar, date, null, date2);
            LoginClient.Request request = deviceAuthMethodHandler.d().g;
            Intrinsics.checkNotNullParameter(token, "token");
            deviceAuthMethodHandler.d().d(new LoginClient.Result(request, q.SUCCESS, token, null, null));
        }
        Dialog dialog = this.l;
        if (dialog != null) {
            dialog.dismiss();
        }
    }

    public final View Q(boolean z) {
        LayoutInflater layoutInflater = requireActivity().getLayoutInflater();
        Intrinsics.checkNotNullExpressionValue(layoutInflater, "requireActivity().layoutInflater");
        View viewInflate = layoutInflater.inflate(z ? R.layout.com_facebook_smart_device_dialog_fragment : R.layout.com_facebook_device_auth_dialog_fragment, (ViewGroup) null);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflater.inflate(getLayo…esId(isSmartLogin), null)");
        View viewFindViewById = viewInflate.findViewById(R.id.progress_bar);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "view.findViewById(R.id.progress_bar)");
        this.q = viewFindViewById;
        View viewFindViewById2 = viewInflate.findViewById(R.id.confirmation_code);
        Intrinsics.e(viewFindViewById2, "null cannot be cast to non-null type android.widget.TextView");
        this.r = (TextView) viewFindViewById2;
        View viewFindViewById3 = viewInflate.findViewById(R.id.cancel_button);
        Intrinsics.e(viewFindViewById3, "null cannot be cast to non-null type android.widget.Button");
        ((Button) viewFindViewById3).setOnClickListener(new View.OnClickListener() { // from class: com.facebook.login.e
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                DeviceAuthDialog this$0 = this.a;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.R();
            }
        });
        View viewFindViewById4 = viewInflate.findViewById(R.id.com_facebook_device_auth_instructions);
        Intrinsics.e(viewFindViewById4, "null cannot be cast to non-null type android.widget.TextView");
        TextView textView = (TextView) viewFindViewById4;
        this.s = textView;
        textView.setText(Html.fromHtml(getString(R.string.com_facebook_device_auth_instructions)));
        return viewInflate;
    }

    public final void R() {
        if (this.u.compareAndSet(false, true)) {
            RequestState requestState = this.x;
            if (requestState != null) {
                com.facebook.devicerequests.internal.b.a(requestState.b);
            }
            DeviceAuthMethodHandler deviceAuthMethodHandler = this.t;
            if (deviceAuthMethodHandler != null) {
                deviceAuthMethodHandler.d().d(new LoginClient.Result(deviceAuthMethodHandler.d().g, q.CANCEL, null, "User canceled log in.", null));
            }
            Dialog dialog = this.l;
            if (dialog != null) {
                dialog.dismiss();
            }
        }
    }

    public final void S(FacebookException ex) {
        Intrinsics.checkNotNullParameter(ex, "ex");
        if (this.u.compareAndSet(false, true)) {
            RequestState requestState = this.x;
            if (requestState != null) {
                com.facebook.devicerequests.internal.b.a(requestState.b);
            }
            DeviceAuthMethodHandler deviceAuthMethodHandler = this.t;
            if (deviceAuthMethodHandler != null) {
                Intrinsics.checkNotNullParameter(ex, "ex");
                LoginClient.Request request = deviceAuthMethodHandler.d().g;
                String message = ex.getMessage();
                ArrayList arrayList = new ArrayList();
                if (message != null) {
                    arrayList.add(message);
                }
                deviceAuthMethodHandler.d().d(new LoginClient.Result(request, q.ERROR, null, TextUtils.join(": ", arrayList), null));
            }
            Dialog dialog = this.l;
            if (dialog != null) {
                dialog.dismiss();
            }
        }
    }

    public final void T(final String str, long j, Long l) {
        com.facebook.x xVar = com.facebook.x.a;
        Bundle bundle = new Bundle();
        bundle.putString("fields", "id,permissions,name");
        Date date = j != 0 ? new Date((j * 1000) + assistantMode.refactored.a.f()) : null;
        final Date date2 = l.longValue() != 0 ? new Date(l.longValue() * 1000) : null;
        AccessToken accessToken = new AccessToken(str, com.facebook.o.b(), "0", null, null, null, null, date, null, date2);
        final Date date3 = date;
        String str2 = com.facebook.t.j;
        com.facebook.t tVarQ = assistantMode.utils.studiableMetadata.b.Q(accessToken, "me", new com.facebook.q() { // from class: com.facebook.login.h
            @Override // com.facebook.q
            public final void a(com.facebook.w response) throws JSONException, Resources.NotFoundException {
                EnumSet enumSet;
                final DeviceAuthDialog this$0 = this.a;
                final String accessToken2 = str;
                final Date date4 = date3;
                final Date date5 = date2;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(accessToken2, "$accessToken");
                Intrinsics.checkNotNullParameter(response, "response");
                if (this$0.u.get()) {
                    return;
                }
                FacebookRequestError facebookRequestError = response.c;
                if (facebookRequestError != null) {
                    FacebookException facebookException = facebookRequestError.i;
                    if (facebookException == null) {
                        facebookException = new FacebookException();
                    }
                    this$0.S(facebookException);
                    return;
                }
                try {
                    JSONObject jSONObject = response.b;
                    if (jSONObject == null) {
                        jSONObject = new JSONObject();
                    }
                    final String string = jSONObject.getString("id");
                    Intrinsics.checkNotNullExpressionValue(string, "jsonObject.getString(\"id\")");
                    final com.quizlet.data.repository.folderset.c cVarA = A.a(jSONObject);
                    String string2 = jSONObject.getString("name");
                    Intrinsics.checkNotNullExpressionValue(string2, "jsonObject.getString(\"name\")");
                    DeviceAuthDialog.RequestState requestState = this$0.x;
                    if (requestState != null) {
                        com.facebook.devicerequests.internal.b.a(requestState.b);
                    }
                    com.facebook.internal.v vVarB = com.facebook.internal.y.b(com.facebook.o.b());
                    if (!Intrinsics.b((vVarB == null || (enumSet = vVarB.c) == null) ? null : Boolean.valueOf(enumSet.contains(com.facebook.internal.F.d)), Boolean.TRUE) || this$0.z) {
                        this$0.P(string, cVarA, accessToken2, date4, date5);
                        return;
                    }
                    this$0.z = true;
                    String string3 = this$0.getResources().getString(R.string.com_facebook_smart_login_confirmation_title);
                    Intrinsics.checkNotNullExpressionValue(string3, "resources.getString(R.st…login_confirmation_title)");
                    String string4 = this$0.getResources().getString(R.string.com_facebook_smart_login_confirmation_continue_as);
                    Intrinsics.checkNotNullExpressionValue(string4, "resources.getString(R.st…confirmation_continue_as)");
                    String string5 = this$0.getResources().getString(R.string.com_facebook_smart_login_confirmation_cancel);
                    Intrinsics.checkNotNullExpressionValue(string5, "resources.getString(R.st…ogin_confirmation_cancel)");
                    String strS = d0.s(new Object[]{string2}, 1, string4, "format(format, *args)");
                    AlertDialog.Builder builder = new AlertDialog.Builder(this$0.getContext());
                    builder.setMessage(string3).setCancelable(true).setNegativeButton(strS, new DialogInterface.OnClickListener() { // from class: com.facebook.login.i
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            DeviceAuthDialog this$02 = this$0;
                            Intrinsics.checkNotNullParameter(this$02, "this$0");
                            String userId = string;
                            Intrinsics.checkNotNullParameter(userId, "$userId");
                            com.quizlet.data.repository.folderset.c permissions = cVarA;
                            Intrinsics.checkNotNullParameter(permissions, "$permissions");
                            String accessToken3 = accessToken2;
                            Intrinsics.checkNotNullParameter(accessToken3, "$accessToken");
                            this$02.P(userId, permissions, accessToken3, date4, date5);
                        }
                    }).setPositiveButton(string5, new DialogInterface.OnClickListener() { // from class: com.facebook.login.j
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            DeviceAuthDialog this$02 = this$0;
                            Intrinsics.checkNotNullParameter(this$02, "this$0");
                            View viewQ = this$02.Q(false);
                            Dialog dialog = this$02.l;
                            if (dialog != null) {
                                dialog.setContentView(viewQ);
                            }
                            LoginClient.Request request = this$02.A;
                            if (request != null) {
                                this$02.X(request);
                            }
                        }
                    });
                    builder.create().show();
                } catch (JSONException e) {
                    this$0.S(new FacebookException(e));
                }
            }
        });
        tVarQ.h = xVar;
        Intrinsics.checkNotNullParameter(bundle, "<set-?>");
        tVarQ.d = bundle;
        tVarQ.d();
    }

    public final void U() {
        RequestState requestState = this.x;
        if (requestState != null) {
            requestState.e = assistantMode.refactored.a.f();
        }
        Bundle bundle = new Bundle();
        RequestState requestState2 = this.x;
        bundle.putString("code", requestState2 != null ? requestState2.c : null);
        StringBuilder sb = new StringBuilder();
        sb.append(com.facebook.o.b());
        sb.append('|');
        AbstractC1554i.k();
        String str = com.facebook.o.f;
        if (str == null) {
            throw new FacebookException("A valid Facebook client token must be set in the AndroidManifest.xml or set by calling FacebookSdk.setClientToken before initializing the sdk. Visit https://developers.facebook.com/docs/android/getting-started#add-app_id for more information.");
        }
        sb.append(str);
        bundle.putString("access_token", sb.toString());
        String str2 = com.facebook.t.j;
        this.v = new com.facebook.t(null, "device/login_status", bundle, com.facebook.x.b, new C1569f(this, 1)).d();
    }

    public final void V() {
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;
        RequestState requestState = this.x;
        Long lValueOf = requestState != null ? Long.valueOf(requestState.d) : null;
        if (lValueOf != null) {
            synchronized (DeviceAuthMethodHandler.d) {
                try {
                    if (DeviceAuthMethodHandler.e == null) {
                        DeviceAuthMethodHandler.e = new ScheduledThreadPoolExecutor(1);
                    }
                    scheduledThreadPoolExecutor = DeviceAuthMethodHandler.e;
                    if (scheduledThreadPoolExecutor == null) {
                        Intrinsics.m("backgroundExecutor");
                        throw null;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            this.w = scheduledThreadPoolExecutor.schedule(new Runnable() { // from class: com.facebook.login.g
                @Override // java.lang.Runnable
                public final void run() {
                    DeviceAuthDialog this$0 = this.a;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    this$0.U();
                }
            }, lValueOf.longValue(), TimeUnit.SECONDS);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00c4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void W(com.facebook.login.DeviceAuthDialog.RequestState r23) {
        /*
            Method dump skipped, instructions count: 277
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.login.DeviceAuthDialog.W(com.facebook.login.DeviceAuthDialog$RequestState):void");
    }

    public final void X(LoginClient.Request request) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.A = request;
        Bundle b = new Bundle();
        b.putString("scope", TextUtils.join(",", request.b));
        String str = request.g;
        Intrinsics.checkNotNullParameter(b, "b");
        if (!J.D(str)) {
            b.putString("redirect_uri", str);
        }
        String str2 = request.i;
        Intrinsics.checkNotNullParameter(b, "b");
        if (!J.D(str2)) {
            b.putString("target_user_id", str2);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(com.facebook.o.b());
        sb.append('|');
        AbstractC1554i.k();
        String str3 = com.facebook.o.f;
        if (str3 == null) {
            throw new FacebookException("A valid Facebook client token must be set in the AndroidManifest.xml or set by calling FacebookSdk.setClientToken before initializing the sdk. Visit https://developers.facebook.com/docs/android/getting-started#add-app_id for more information.");
        }
        sb.append(str3);
        b.putString("access_token", sb.toString());
        com.facebook.devicerequests.internal.b bVar = com.facebook.devicerequests.internal.b.a;
        String str4 = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.devicerequests.internal.b.class)) {
            try {
                HashMap map = new HashMap();
                String DEVICE = Build.DEVICE;
                Intrinsics.checkNotNullExpressionValue(DEVICE, "DEVICE");
                map.put("device", DEVICE);
                String MODEL = Build.MODEL;
                Intrinsics.checkNotNullExpressionValue(MODEL, "MODEL");
                map.put(DtbDeviceData.DEVICE_DATA_MODEL_KEY, MODEL);
                String string = new JSONObject(map).toString();
                Intrinsics.checkNotNullExpressionValue(string, "JSONObject(deviceInfo as Map<*, *>).toString()");
                str4 = string;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(com.facebook.devicerequests.internal.b.class, th);
            }
        }
        b.putString("device_info", str4);
        String str5 = com.facebook.t.j;
        new com.facebook.t(null, "device/login", b, com.facebook.x.b, new C1569f(this, 0)).d();
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        RequestState requestState;
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewOnCreateView = super.onCreateView(inflater, viewGroup, bundle);
        I iRequireActivity = requireActivity();
        Intrinsics.e(iRequireActivity, "null cannot be cast to non-null type com.facebook.FacebookActivity");
        u uVar = (u) ((FacebookActivity) iRequireActivity).b;
        this.t = (DeviceAuthMethodHandler) (uVar != null ? uVar.G().g() : null);
        if (bundle != null && (requestState = (RequestState) bundle.getParcelable("request_state")) != null) {
            W(requestState);
        }
        return viewOnCreateView;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        this.y = true;
        this.u.set(true);
        super.onDestroyView();
        com.facebook.u uVar = this.v;
        if (uVar != null) {
            uVar.cancel(true);
        }
        ScheduledFuture scheduledFuture = this.w;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        if (this.y) {
            return;
        }
        R();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        super.onSaveInstanceState(outState);
        if (this.x != null) {
            outState.putParcelable("request_state", this.x);
        }
    }
}
