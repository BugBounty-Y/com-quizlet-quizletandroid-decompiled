package com.quizlet.quizletandroid.util.links;

import android.net.Uri;
import com.auth0.android.jwt.JWT;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.utm.a;
import com.quizlet.utm.sources.b;
import com.quizlet.utmhelper.d;
import kotlin.jvm.internal.Intrinsics;
import timber.log.c;

/* loaded from: classes3.dex */
public abstract class a {
    public static void a(EventLogger eventLogger, Uri uri, String str) {
        EventLogger eventLogger2;
        JWT jwt;
        String queryParameter = uri.getQueryParameter("et");
        if (queryParameter == null) {
            return;
        }
        if (queryParameter.length() == 0) {
            eventLogger.k("Missing email tracking param detected : " + uri);
            return;
        }
        if (!queryParameter.endsWith(".")) {
            queryParameter = queryParameter.concat(".");
        }
        try {
            jwt = new JWT(queryParameter);
            eventLogger2 = eventLogger;
        } catch (Exception e) {
            e = e;
            eventLogger2 = eventLogger;
        }
        try {
            eventLogger2.j(jwt.b("email").b(), jwt.b("tag").b(), jwt.b("sourceType").b(), jwt.b("sourceKey").a(), uri.getPath(), str);
            eventLogger2.I("deeplink_click");
        } catch (Exception e2) {
            e = e2;
            Exception exc = e;
            eventLogger2.k("Failed to parse email tracking link data : " + uri);
            c.a(exc);
        }
    }

    public static void b(EventLogger eventLogger, Uri uri, com.quizlet.utmhelper.c cVar, Long l, String str, Integer num) {
        b source;
        com.quizlet.utm.mediums.b medium;
        com.quizlet.utm.campaigns.b campaign;
        String queryParameter = uri.getQueryParameter("i");
        String queryParameter2 = uri.getQueryParameter("x");
        String queryParameter3 = uri.getQueryParameter("utm_source");
        String queryParameter4 = uri.getQueryParameter("utm_medium");
        String queryParameter5 = uri.getQueryParameter("utm_campaign");
        String value = null;
        if (queryParameter2 == null && queryParameter == null) {
            if (queryParameter3 == null && queryParameter4 == null && queryParameter5 == null && l == null && str == null) {
                return;
            }
            eventLogger.o(new com.quizlet.utmhelper.a(null, queryParameter5, queryParameter4, queryParameter3), num, l, uri.toString(), str);
            return;
        }
        if (queryParameter == null) {
            queryParameter = "";
        }
        if (queryParameter2 == null) {
            queryParameter2 = "";
        }
        com.quizlet.utmhelper.b info = new com.quizlet.utmhelper.b(queryParameter, queryParameter2);
        ((d) cVar).getClass();
        Intrinsics.checkNotNullParameter(info, "info");
        a.C0023a c0023aDecodeUtmParams = com.quizlet.utm.a.decodeUtmParams(new a.b(queryParameter, queryParameter2));
        Long userId = c0023aDecodeUtmParams.getUserId();
        a.c params = c0023aDecodeUtmParams.getParams();
        String value2 = (params == null || (campaign = params.getCampaign()) == null) ? null : campaign.getValue();
        a.c params2 = c0023aDecodeUtmParams.getParams();
        String value3 = (params2 == null || (medium = params2.getMedium()) == null) ? null : medium.getValue();
        a.c params3 = c0023aDecodeUtmParams.getParams();
        if (params3 != null && (source = params3.getSource()) != null) {
            value = source.getValue();
        }
        eventLogger.o(new com.quizlet.utmhelper.a(userId, value2, value3, value), num, l, uri.toString(), str);
    }
}
