package com.braze.events;

import com.braze.requests.n;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class BrazeNetworkFailureEvent {
    private final n brazeRequest;
    private final com.braze.communication.d httpConnectorResult;
    private final Long requestInitiationTime;
    private final RequestType requestType;
    private final String requestUrl;
    private final int responseCode;
    private final Map<String, String> responseHeaders;

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class RequestType {
        private static final /* synthetic */ kotlin.enums.a $ENTRIES;
        private static final /* synthetic */ RequestType[] $VALUES;
        public static final RequestType CONTENT_CARDS_SYNC = new RequestType("CONTENT_CARDS_SYNC", 0);
        public static final RequestType NEWS_FEED_SYNC = new RequestType("NEWS_FEED_SYNC", 1);
        public static final RequestType OTHER = new RequestType("OTHER", 2);

        private static final /* synthetic */ RequestType[] $values() {
            return new RequestType[]{CONTENT_CARDS_SYNC, NEWS_FEED_SYNC, OTHER};
        }

        static {
            RequestType[] requestTypeArr$values = $values();
            $VALUES = requestTypeArr$values;
            $ENTRIES = AbstractC3328d.f(requestTypeArr$values);
        }

        private RequestType(String str, int i) {
        }

        public static RequestType valueOf(String str) {
            return (RequestType) Enum.valueOf(RequestType.class, str);
        }

        public static RequestType[] values() {
            return (RequestType[]) $VALUES.clone();
        }
    }

    public BrazeNetworkFailureEvent(n brazeRequest, com.braze.communication.d httpConnectorResult) {
        Intrinsics.checkNotNullParameter(brazeRequest, "brazeRequest");
        Intrinsics.checkNotNullParameter(httpConnectorResult, "httpConnectorResult");
        this.brazeRequest = brazeRequest;
        this.httpConnectorResult = httpConnectorResult;
        this.responseCode = httpConnectorResult.a;
        this.responseHeaders = httpConnectorResult.b;
        com.braze.requests.b bVar = (com.braze.requests.b) brazeRequest;
        this.requestInitiationTime = bVar.d;
        this.requestUrl = bVar.e().a;
        RequestType requestType = brazeRequest instanceof com.braze.requests.e ? RequestType.CONTENT_CARDS_SYNC : (!(brazeRequest instanceof com.braze.requests.f) || ((com.braze.requests.f) brazeRequest).j.b == null) ? RequestType.OTHER : RequestType.NEWS_FEED_SYNC;
        this.requestType = requestType;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BrazeNetworkFailureEvent)) {
            return false;
        }
        BrazeNetworkFailureEvent brazeNetworkFailureEvent = (BrazeNetworkFailureEvent) obj;
        return Intrinsics.b(this.brazeRequest, brazeNetworkFailureEvent.brazeRequest) && Intrinsics.b(this.httpConnectorResult, brazeNetworkFailureEvent.httpConnectorResult);
    }

    public int hashCode() {
        return this.httpConnectorResult.hashCode() + (this.brazeRequest.hashCode() * 31);
    }

    public String toString() {
        return "BrazeNetworkFailureEvent(brazeRequest=" + this.brazeRequest + ", httpConnectorResult=" + this.httpConnectorResult + ')';
    }
}
