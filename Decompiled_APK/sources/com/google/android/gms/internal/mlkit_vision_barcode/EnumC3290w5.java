package com.google.android.gms.internal.mlkit_vision_barcode;

import com.comscore.streaming.ContentType;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.w5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public enum EnumC3290w5 implements J {
    NO_ERROR(0),
    /* JADX INFO: Fake field, exist only in values array */
    INCOMPATIBLE_INPUT(1),
    /* JADX INFO: Fake field, exist only in values array */
    INCOMPATIBLE_OUTPUT(2),
    /* JADX INFO: Fake field, exist only in values array */
    INCOMPATIBLE_TFLITE_VERSION(3),
    /* JADX INFO: Fake field, exist only in values array */
    MISSING_OP(4),
    /* JADX INFO: Fake field, exist only in values array */
    DATA_TYPE_ERROR(6),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(7),
    /* JADX INFO: Fake field, exist only in values array */
    TFLITE_UNKNOWN_ERROR(8),
    /* JADX INFO: Fake field, exist only in values array */
    MEDIAPIPE_ERROR(9),
    /* JADX INFO: Fake field, exist only in values array */
    TIME_OUT_FETCHING_MODEL_METADATA(5),
    MODEL_NOT_DOWNLOADED(100),
    /* JADX INFO: Fake field, exist only in values array */
    URI_EXPIRED(101),
    /* JADX INFO: Fake field, exist only in values array */
    NO_NETWORK_CONNECTION(102),
    /* JADX INFO: Fake field, exist only in values array */
    METERED_NETWORK(103),
    /* JADX INFO: Fake field, exist only in values array */
    DOWNLOAD_FAILED(104),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(111),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(ContentType.LONG_FORM_ON_DEMAND),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(ContentType.LIVE),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(114),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(115),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(116),
    OPTIONAL_MODULE_NOT_AVAILABLE(201),
    OPTIONAL_MODULE_INIT_ERROR(202),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(203),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(204),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(205),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SYNC_FAILED),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(301),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(302),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(303),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(304),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(305),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(400),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(401),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(402),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(403),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(404),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(com.pubmatic.sdk.video.a.MEDIA_FILE_DISPLAY_ERROR),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(406),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(com.pubmatic.sdk.video.a.VERIFICATION_EXECUTION_ERROR),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(501),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(601),
    /* JADX INFO: Fake field, exist only in values array */
    GOOGLE_PLAY_SERVICES_VERSION_TOO_OLD(602),
    /* JADX INFO: Fake field, exist only in values array */
    LOW_MEMORY(603),
    UNKNOWN_ERROR(9999);

    public final int a;

    EnumC3290w5(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.J
    public final int zza() {
        return this.a;
    }
}
