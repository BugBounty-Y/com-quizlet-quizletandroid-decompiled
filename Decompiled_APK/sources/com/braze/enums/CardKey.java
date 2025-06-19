package com.braze.enums;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.braze.communication.dust.j;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes.dex */
public final class CardKey {
    private static final /* synthetic */ kotlin.enums.a $ENTRIES;
    private static final /* synthetic */ CardKey[] $VALUES;
    public static final b Companion;
    private static final Map<String, CardType> cardTypeMap;
    private final String contentCardsKey;
    private final String feedKey;
    public static final CardKey ID = new CardKey("ID", 0, "id", "id");
    public static final CardKey VIEWED = new CardKey("VIEWED", 1, "viewed", "v");
    public static final CardKey CREATED = new CardKey("CREATED", 2, "created", OTCCPAGeolocationConstants.CA);
    public static final CardKey EXPIRES_AT = new CardKey("EXPIRES_AT", 3, "expires_at", "ea");
    public static final CardKey EXTRAS = new CardKey("EXTRAS", 4, "extras", "e");
    public static final CardKey OPEN_URI_IN_WEBVIEW = new CardKey("OPEN_URI_IN_WEBVIEW", 5, "use_webview", "uw");
    public static final CardKey TYPE = new CardKey("TYPE", 6, DBUserFields.Names.USER_UPGRADE_TYPE, "tp");
    public static final CardKey CATEGORIES = new CardKey("CATEGORIES", 7, "categories", "");
    public static final CardKey UPDATED = new CardKey("UPDATED", 8, "updated", "");
    public static final CardKey DISMISSED = new CardKey("DISMISSED", 9, "", "d");
    public static final CardKey REMOVED = new CardKey("REMOVED", 10, "", "r");
    public static final CardKey PINNED = new CardKey("PINNED", 11, "", "p");
    public static final CardKey DISMISSIBLE = new CardKey("DISMISSIBLE", 12, "", "db");
    public static final CardKey IS_TEST = new CardKey("IS_TEST", 13, "", "t");
    public static final CardKey READ = new CardKey("READ", 14, "", "read");
    public static final CardKey CLICKED = new CardKey("CLICKED", 15, "", "cl");
    public static final CardKey IMAGE_ONLY_IMAGE = new CardKey("IMAGE_ONLY_IMAGE", 16, "image", "i");
    public static final CardKey IMAGE_ONLY_URL = new CardKey("IMAGE_ONLY_URL", 17, DTBMetricsConfiguration.APSMETRICS_URL, "u");
    public static final CardKey IMAGE_ONLY_DOMAIN = new CardKey("IMAGE_ONLY_DOMAIN", 18, "domain", "");
    public static final CardKey IMAGE_ONLY_ASPECT_RATIO = new CardKey("IMAGE_ONLY_ASPECT_RATIO", 19, "aspect_ratio", "ar");
    public static final CardKey CAPTIONED_IMAGE_IMAGE = new CardKey("CAPTIONED_IMAGE_IMAGE", 20, "image", "i");
    public static final CardKey CAPTIONED_IMAGE_TITLE = new CardKey("CAPTIONED_IMAGE_TITLE", 21, "title", "tt");
    public static final CardKey CAPTIONED_IMAGE_DESCRIPTION = new CardKey("CAPTIONED_IMAGE_DESCRIPTION", 22, OTUXParamsKeys.OT_UX_DESCRIPTION, "ds");
    public static final CardKey CAPTIONED_IMAGE_URL = new CardKey("CAPTIONED_IMAGE_URL", 23, DTBMetricsConfiguration.APSMETRICS_URL, "u");
    public static final CardKey CAPTIONED_IMAGE_DOMAIN = new CardKey("CAPTIONED_IMAGE_DOMAIN", 24, "domain", "dm");
    public static final CardKey CAPTIONED_IMAGE_ASPECT_RATIO = new CardKey("CAPTIONED_IMAGE_ASPECT_RATIO", 25, "aspect_ratio", "ar");
    public static final CardKey TEXT_ANNOUNCEMENT_TITLE = new CardKey("TEXT_ANNOUNCEMENT_TITLE", 26, "title", "tt");
    public static final CardKey TEXT_ANNOUNCEMENT_DESCRIPTION = new CardKey("TEXT_ANNOUNCEMENT_DESCRIPTION", 27, OTUXParamsKeys.OT_UX_DESCRIPTION, "ds");
    public static final CardKey TEXT_ANNOUNCEMENT_URL = new CardKey("TEXT_ANNOUNCEMENT_URL", 28, DTBMetricsConfiguration.APSMETRICS_URL, "u");
    public static final CardKey TEXT_ANNOUNCEMENT_DOMAIN = new CardKey("TEXT_ANNOUNCEMENT_DOMAIN", 29, "domain", "dm");
    public static final CardKey SHORT_NEWS_IMAGE = new CardKey("SHORT_NEWS_IMAGE", 30, "image", "i");
    public static final CardKey SHORT_NEWS_TITLE = new CardKey("SHORT_NEWS_TITLE", 31, "title", "tt");
    public static final CardKey SHORT_NEWS_DESCRIPTION = new CardKey("SHORT_NEWS_DESCRIPTION", 32, OTUXParamsKeys.OT_UX_DESCRIPTION, "ds");
    public static final CardKey SHORT_NEWS_URL = new CardKey("SHORT_NEWS_URL", 33, DTBMetricsConfiguration.APSMETRICS_URL, "u");
    public static final CardKey SHORT_NEWS_DOMAIN = new CardKey("SHORT_NEWS_DOMAIN", 34, "domain", "dm");

    @Metadata
    public static final class Provider {
        private final boolean isContentCardProvider;
        public static final c Companion = new c();
        public static final Provider CONTENT_CARDS = new Provider(true);
        public static final Provider NEWS_FEED = new Provider(false);

        public Provider(boolean z) {
            this.isContentCardProvider = z;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String getCardTypeFromJson$lambda$0(JSONObject jSONObject) {
            return assistantMode.refactored.a.j("Short News card doesn't contain image url, parsing type as Text Announcement. JSON: ", jSONObject);
        }

        public final CardType getCardTypeFromJson(JSONObject jsonObject) {
            String optionalString;
            Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
            String optionalString2 = JsonUtils.getOptionalString(jsonObject, getKey(CardKey.TYPE));
            if (optionalString2 != null && optionalString2.length() != 0 && this.isContentCardProvider && optionalString2.equals("short_news") && ((optionalString = JsonUtils.getOptionalString(jsonObject, getKey(CardKey.SHORT_NEWS_IMAGE))) == null || optionalString.length() == 0)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new j(jsonObject, 1), 6, (Object) null);
                optionalString2 = "text_announcement";
            }
            return CardKey.cardTypeMap.containsKey(optionalString2) ? (CardType) CardKey.cardTypeMap.get(optionalString2) : CardType.DEFAULT;
        }

        public final String getKey(CardKey key) {
            Intrinsics.checkNotNullParameter(key, "key");
            return this.isContentCardProvider ? key.getContentCardsKey() : key.getFeedKey();
        }

        public final boolean isContentCardProvider() {
            return this.isContentCardProvider;
        }
    }

    private static final /* synthetic */ CardKey[] $values() {
        return new CardKey[]{ID, VIEWED, CREATED, EXPIRES_AT, EXTRAS, OPEN_URI_IN_WEBVIEW, TYPE, CATEGORIES, UPDATED, DISMISSED, REMOVED, PINNED, DISMISSIBLE, IS_TEST, READ, CLICKED, IMAGE_ONLY_IMAGE, IMAGE_ONLY_URL, IMAGE_ONLY_DOMAIN, IMAGE_ONLY_ASPECT_RATIO, CAPTIONED_IMAGE_IMAGE, CAPTIONED_IMAGE_TITLE, CAPTIONED_IMAGE_DESCRIPTION, CAPTIONED_IMAGE_URL, CAPTIONED_IMAGE_DOMAIN, CAPTIONED_IMAGE_ASPECT_RATIO, TEXT_ANNOUNCEMENT_TITLE, TEXT_ANNOUNCEMENT_DESCRIPTION, TEXT_ANNOUNCEMENT_URL, TEXT_ANNOUNCEMENT_DOMAIN, SHORT_NEWS_IMAGE, SHORT_NEWS_TITLE, SHORT_NEWS_DESCRIPTION, SHORT_NEWS_URL, SHORT_NEWS_DOMAIN};
    }

    /* JADX WARN: Type inference failed for: r0v37, types: [com.braze.enums.b] */
    static {
        CardKey[] cardKeyArr$values = $values();
        $VALUES = cardKeyArr$values;
        $ENTRIES = AbstractC3328d.f(cardKeyArr$values);
        Companion = new Object() { // from class: com.braze.enums.b
        };
        cardTypeMap = V.f(new Pair("banner_image", CardType.IMAGE), new Pair("captioned_image", CardType.CAPTIONED_IMAGE), new Pair("text_announcement", CardType.TEXT_ANNOUNCEMENT), new Pair("short_news", CardType.SHORT_NEWS), new Pair("control", CardType.CONTROL));
    }

    private CardKey(String str, int i, String str2, String str3) {
        this.feedKey = str2;
        this.contentCardsKey = str3;
    }

    public static CardKey valueOf(String str) {
        return (CardKey) Enum.valueOf(CardKey.class, str);
    }

    public static CardKey[] values() {
        return (CardKey[]) $VALUES.clone();
    }

    public final String getContentCardsKey() {
        return this.contentCardsKey;
    }

    public final String getFeedKey() {
        return this.feedKey;
    }
}
