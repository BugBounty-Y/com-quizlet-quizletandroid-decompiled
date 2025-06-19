package com.google.firebase.perf.metrics.validator;

import android.content.Context;
import android.content.res.Resources;
import com.google.android.gms.internal.mlkit_vision_common.M4;
import com.google.firebase.perf.v1.r;
import com.google.firebase.perf.v1.t;
import java.net.URI;

/* loaded from: classes2.dex */
public final class c extends e {
    public static final com.google.firebase.perf.logging.a c = com.google.firebase.perf.logging.a.d();
    public final t a;
    public final Context b;

    public c(t tVar, Context context) {
        this.b = context;
        this.a = tVar;
    }

    @Override // com.google.firebase.perf.metrics.validator.e
    public final boolean a() {
        URI uriCreate;
        t tVar = this.a;
        String strT = tVar.T();
        boolean zIsEmpty = strT == null ? true : strT.trim().isEmpty();
        com.google.firebase.perf.logging.a aVar = c;
        if (zIsEmpty) {
            aVar.f("URL is missing:" + tVar.T());
            return false;
        }
        String strT2 = tVar.T();
        if (strT2 == null) {
            uriCreate = null;
        } else {
            try {
                uriCreate = URI.create(strT2);
            } catch (IllegalArgumentException | IllegalStateException e) {
                aVar.g("getResultUrl throws exception %s", e.getMessage());
            }
        }
        if (uriCreate == null) {
            aVar.f("URL cannot be parsed");
            return false;
        }
        Context context = this.b;
        Resources resources = context.getResources();
        int identifier = resources.getIdentifier("firebase_performance_whitelisted_domains", "array", context.getPackageName());
        if (identifier != 0) {
            com.google.firebase.perf.logging.a.d().a();
            if (M4.b == null) {
                M4.b = resources.getStringArray(identifier);
            }
            String host = uriCreate.getHost();
            if (host != null) {
                for (String str : M4.b) {
                    if (!host.contains(str)) {
                    }
                }
                aVar.f("URL fails allowlist rule: " + uriCreate);
                return false;
            }
        }
        String host2 = uriCreate.getHost();
        if (host2 == null || host2.trim().isEmpty() || host2.length() > 255) {
            aVar.f("URL host is null or invalid");
            return false;
        }
        String scheme = uriCreate.getScheme();
        if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
            aVar.f("URL scheme is null or invalid");
            return false;
        }
        if (uriCreate.getUserInfo() != null) {
            aVar.f("URL user info is null");
            return false;
        }
        int port = uriCreate.getPort();
        if (port != -1 && port <= 0) {
            aVar.f("URL port is less than or equal to 0");
            return false;
        }
        r rVarL = tVar.V() ? tVar.L() : null;
        if (rVarL == null || rVarL == r.HTTP_METHOD_UNKNOWN) {
            aVar.f("HTTP Method is null or invalid: " + tVar.L());
            return false;
        }
        if (tVar.W() && tVar.M() <= 0) {
            aVar.f("HTTP ResponseCode is a negative value:" + tVar.M());
            return false;
        }
        if (tVar.X() && tVar.O() < 0) {
            aVar.f("Request Payload is a negative value:" + tVar.O());
            return false;
        }
        if (tVar.Y() && tVar.P() < 0) {
            aVar.f("Response Payload is a negative value:" + tVar.P());
            return false;
        }
        if (!tVar.U() || tVar.J() <= 0) {
            aVar.f("Start time of the request is null, or zero, or a negative value:" + tVar.J());
            return false;
        }
        if (tVar.Z() && tVar.Q() < 0) {
            aVar.f("Time to complete the request is a negative value:" + tVar.Q());
            return false;
        }
        if (tVar.b0() && tVar.S() < 0) {
            aVar.f("Time from the start of the request to the start of the response is null or a negative value:" + tVar.S());
            return false;
        }
        if (!tVar.a0() || tVar.R() <= 0) {
            aVar.f("Time from the start of the request to the end of the response is null, negative or zero:" + tVar.R());
            return false;
        }
        if (tVar.W()) {
            return true;
        }
        aVar.f("Did not receive a HTTP Response Code");
        return false;
    }
}
