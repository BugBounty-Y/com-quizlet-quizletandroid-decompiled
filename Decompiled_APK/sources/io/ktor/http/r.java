package io.ktor.http;

import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements Comparable {
    public static final r c;
    public static final r d;
    public static final r e;
    public static final r f;
    public static final r g;
    public final int a;
    public final String b;

    static {
        r rVar = new r(100, "Continue");
        r rVar2 = new r(101, "Switching Protocols");
        r rVar3 = new r(102, "Processing");
        r rVar4 = new r(200, "OK");
        r rVar5 = new r(201, "Created");
        r rVar6 = new r(202, "Accepted");
        r rVar7 = new r(203, "Non-Authoritative Information");
        r rVar8 = new r(204, "No Content");
        r rVar9 = new r(205, "Reset Content");
        r rVar10 = new r(OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF, "Partial Content");
        r rVar11 = new r(OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SYNC_FAILED, "Multi-Status");
        r rVar12 = new r(300, "Multiple Choices");
        r rVar13 = new r(301, "Moved Permanently");
        c = rVar13;
        r rVar14 = new r(302, "Found");
        d = rVar14;
        r rVar15 = new r(303, "See Other");
        e = rVar15;
        r rVar16 = new r(304, "Not Modified");
        r rVar17 = new r(305, "Use Proxy");
        r rVar18 = new r(306, "Switch Proxy");
        r rVar19 = new r(307, "Temporary Redirect");
        f = rVar19;
        r rVar20 = new r(308, "Permanent Redirect");
        g = rVar20;
        List listJ = B.j(rVar, rVar2, rVar3, rVar4, rVar5, rVar6, rVar7, rVar8, rVar9, rVar10, rVar11, rVar12, rVar13, rVar14, rVar15, rVar16, rVar17, rVar18, rVar19, rVar20, new r(400, "Bad Request"), new r(401, "Unauthorized"), new r(402, "Payment Required"), new r(403, "Forbidden"), new r(404, "Not Found"), new r(com.pubmatic.sdk.video.a.MEDIA_FILE_DISPLAY_ERROR, "Method Not Allowed"), new r(406, "Not Acceptable"), new r(com.pubmatic.sdk.video.a.VERIFICATION_EXECUTION_ERROR, "Proxy Authentication Required"), new r(408, "Request Timeout"), new r(409, "Conflict"), new r(410, "Gone"), new r(411, "Length Required"), new r(412, "Precondition Failed"), new r(413, "Payload Too Large"), new r(414, "Request-URI Too Long"), new r(415, "Unsupported Media Type"), new r(416, "Requested Range Not Satisfiable"), new r(417, "Expectation Failed"), new r(422, "Unprocessable Entity"), new r(423, "Locked"), new r(424, "Failed Dependency"), new r(425, "Too Early"), new r(426, "Upgrade Required"), new r(429, "Too Many Requests"), new r(431, "Request Header Fields Too Large"), new r(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, "Internal Server Error"), new r(501, "Not Implemented"), new r(502, "Bad Gateway"), new r(503, "Service Unavailable"), new r(504, "Gateway Timeout"), new r(505, "HTTP Version Not Supported"), new r(506, "Variant Also Negotiates"), new r(507, "Insufficient Storage"));
        int iA = U.a(C.q(listJ, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj : listJ) {
            linkedHashMap.put(Integer.valueOf(((r) obj).a), obj);
        }
    }

    public r(int i, String description) {
        Intrinsics.checkNotNullParameter(description, "description");
        this.a = i;
        this.b = description;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        r other = (r) obj;
        Intrinsics.checkNotNullParameter(other, "other");
        return this.a - other.a;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof r) && ((r) obj).a == this.a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return this.a + ' ' + this.b;
    }
}
