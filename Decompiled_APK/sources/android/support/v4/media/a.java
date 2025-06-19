package android.support.v4.media;

import android.content.Intent;
import android.content.IntentSender;
import android.graphics.Bitmap;
import android.media.MediaDescription;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.support.v4.media.a;
import android.support.v4.media.session.c;
import android.support.v4.os.ResultReceiver;
import android.support.v4.os.b;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.IntentSenderRequest;
import androidx.versionedparcelable.ParcelImpl;
import com.auth0.android.jwt.JWT;
import com.comscore.streaming.EventType;
import com.facebook.AccessToken;
import com.facebook.AuthenticationToken;
import com.facebook.AuthenticationTokenClaims;
import com.facebook.AuthenticationTokenHeader;
import com.facebook.FacebookRequestError;
import com.facebook.GraphRequest$ParcelableResourceWithMimeType;
import com.facebook.Profile;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector$SelectionOverride;
import com.google.android.exoplayer2.video.ColorInfo;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.formats.PublisherAdViewOptions;
import com.google.android.gms.ads.internal.offline.buffering.zza;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.overlay.zzc;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.internal.util.zzbb;
import com.google.android.gms.ads.internal.zzl;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(final Parcel parcel) {
        Bundle bundle;
        boolean zM = false;
        int iO = 0;
        boolean zM2 = false;
        b bVar = null;
        String strG = null;
        String strG2 = null;
        IBinder iBinderN = null;
        switch (this.a) {
            case 0:
                return new Parcelable(parcel) { // from class: android.support.v4.media.MediaBrowserCompat$MediaItem
                    public static final Parcelable.Creator<MediaBrowserCompat$MediaItem> CREATOR = new a(0);
                    public final int a;
                    public final MediaDescriptionCompat b;

                    {
                        this.a = parcel.readInt();
                        this.b = MediaDescriptionCompat.CREATOR.createFromParcel(parcel);
                    }

                    @Override // android.os.Parcelable
                    public final int describeContents() {
                        return 0;
                    }

                    public final String toString() {
                        return "MediaItem{mFlags=" + this.a + ", mDescription=" + this.b + '}';
                    }

                    @Override // android.os.Parcelable
                    public final void writeToParcel(Parcel parcel2, int i) {
                        parcel2.writeInt(this.a);
                        this.b.writeToParcel(parcel2, i);
                    }
                };
            case 1:
                Object objCreateFromParcel = MediaDescription.CREATOR.createFromParcel(parcel);
                if (objCreateFromParcel == null) {
                    return null;
                }
                MediaDescription mediaDescription = (MediaDescription) objCreateFromParcel;
                String mediaId = mediaDescription.getMediaId();
                CharSequence title = mediaDescription.getTitle();
                CharSequence subtitle = mediaDescription.getSubtitle();
                CharSequence description = mediaDescription.getDescription();
                Bitmap iconBitmap = mediaDescription.getIconBitmap();
                Uri iconUri = mediaDescription.getIconUri();
                Bundle extras = mediaDescription.getExtras();
                if (extras != null) {
                    extras = c.a(extras);
                }
                Uri mediaUri = extras != null ? (Uri) extras.getParcelable("android.support.v4.media.description.MEDIA_URI") : null;
                if (mediaUri == null) {
                    bundle = extras;
                } else if (extras.containsKey("android.support.v4.media.description.NULL_BUNDLE_FLAG") && extras.size() == 2) {
                    bundle = null;
                } else {
                    extras.remove("android.support.v4.media.description.MEDIA_URI");
                    extras.remove("android.support.v4.media.description.NULL_BUNDLE_FLAG");
                    bundle = extras;
                }
                if (mediaUri == null) {
                    mediaUri = mediaDescription.getMediaUri();
                }
                MediaDescriptionCompat mediaDescriptionCompat = new MediaDescriptionCompat(mediaId, title, subtitle, description, iconBitmap, iconUri, bundle, mediaUri);
                mediaDescriptionCompat.i = mediaDescription;
                return mediaDescriptionCompat;
            case 2:
                return new MediaMetadataCompat(parcel);
            case 3:
                return new RatingCompat(parcel.readFloat(), parcel.readInt());
            case 4:
                ResultReceiver resultReceiver = new ResultReceiver();
                IBinder strongBinder = parcel.readStrongBinder();
                int i = android.support.v4.os.c.b;
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface(b.Q);
                    if (iInterfaceQueryLocalInterface == null || !(iInterfaceQueryLocalInterface instanceof b)) {
                        android.support.v4.os.a aVar = new android.support.v4.os.a();
                        aVar.a = strongBinder;
                        bVar = aVar;
                    } else {
                        bVar = (b) iInterfaceQueryLocalInterface;
                    }
                }
                resultReceiver.a = bVar;
                return resultReceiver;
            case 5:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new ActivityResult(parcel.readInt(), parcel.readInt() != 0 ? (Intent) Intent.CREATOR.createFromParcel(parcel) : null);
            case 6:
                Intrinsics.checkNotNullParameter(parcel, "inParcel");
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                Parcelable parcelable = parcel.readParcelable(IntentSender.class.getClassLoader());
                Intrinsics.d(parcelable);
                return new IntentSenderRequest((IntentSender) parcelable, (Intent) parcel.readParcelable(Intent.class.getClassLoader()), parcel.readInt(), parcel.readInt());
            case 7:
                return new ParcelImpl(parcel);
            case 8:
                return new JWT(parcel.readString());
            case 9:
                Intrinsics.checkNotNullParameter(parcel, "source");
                return new AccessToken(parcel);
            case 10:
                Intrinsics.checkNotNullParameter(parcel, "source");
                return new AuthenticationToken(parcel);
            case 11:
                Intrinsics.checkNotNullParameter(parcel, "source");
                return new AuthenticationTokenClaims(parcel);
            case 12:
                Intrinsics.checkNotNullParameter(parcel, "source");
                return new AuthenticationTokenHeader(parcel);
            case 13:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new FacebookRequestError(parcel.readInt(), parcel.readInt(), parcel.readInt(), parcel.readString(), parcel.readString(), parcel.readString(), parcel.readString(), null, null, false);
            case 14:
                Intrinsics.checkNotNullParameter(parcel, "source");
                return new GraphRequest$ParcelableResourceWithMimeType(parcel);
            case 15:
                Intrinsics.checkNotNullParameter(parcel, "source");
                return new Profile(parcel);
            case 16:
                return new Format(parcel);
            case 17:
                return new DrmInitData(parcel);
            case 18:
                return new Metadata(parcel);
            case 19:
                return new TrackGroup(parcel);
            case 20:
                return new TrackGroupArray(parcel);
            case 21:
                return new Parcelable(parcel) { // from class: com.google.android.exoplayer2.trackselection.DefaultTrackSelector$SelectionOverride
                    public static final Parcelable.Creator<DefaultTrackSelector$SelectionOverride> CREATOR = new a(21);
                    public final int a;
                    public final int[] b;
                    public final int c;

                    {
                        this.a = parcel.readInt();
                        int[] iArr = new int[parcel.readByte()];
                        this.b = iArr;
                        parcel.readIntArray(iArr);
                        this.c = parcel.readInt();
                    }

                    @Override // android.os.Parcelable
                    public final int describeContents() {
                        return 0;
                    }

                    public final boolean equals(Object obj) {
                        if (this == obj) {
                            return true;
                        }
                        if (obj != null && DefaultTrackSelector$SelectionOverride.class == obj.getClass()) {
                            DefaultTrackSelector$SelectionOverride defaultTrackSelector$SelectionOverride = (DefaultTrackSelector$SelectionOverride) obj;
                            if (this.a == defaultTrackSelector$SelectionOverride.a && Arrays.equals(this.b, defaultTrackSelector$SelectionOverride.b) && this.c == defaultTrackSelector$SelectionOverride.c) {
                                return true;
                            }
                        }
                        return false;
                    }

                    public final int hashCode() {
                        return ((Arrays.hashCode(this.b) + (this.a * 31)) * 31) + this.c;
                    }

                    @Override // android.os.Parcelable
                    public final void writeToParcel(Parcel parcel2, int i2) {
                        parcel2.writeInt(this.a);
                        int[] iArr = this.b;
                        parcel2.writeInt(iArr.length);
                        parcel2.writeIntArray(iArr);
                        parcel2.writeInt(this.c);
                    }
                };
            case EventType.WINDOW_STATE /* 22 */:
                return new ColorInfo(parcel);
            case EventType.AUDIO /* 23 */:
                int iS = AbstractC3471i3.s(parcel);
                while (parcel.dataPosition() < iS) {
                    int i2 = parcel.readInt();
                    if (((char) i2) != 1) {
                        AbstractC3471i3.r(i2, parcel);
                    } else {
                        zM = AbstractC3471i3.m(i2, parcel);
                    }
                }
                AbstractC3471i3.l(iS, parcel);
                return new AdManagerAdViewOptions(zM);
            case EventType.VIDEO /* 24 */:
                int iS2 = AbstractC3471i3.s(parcel);
                IBinder iBinderN2 = null;
                while (parcel.dataPosition() < iS2) {
                    int i3 = parcel.readInt();
                    char c = (char) i3;
                    if (c == 1) {
                        zM2 = AbstractC3471i3.m(i3, parcel);
                    } else if (c == 2) {
                        iBinderN = AbstractC3471i3.n(i3, parcel);
                    } else if (c != 3) {
                        AbstractC3471i3.r(i3, parcel);
                    } else {
                        iBinderN2 = AbstractC3471i3.n(i3, parcel);
                    }
                }
                AbstractC3471i3.l(iS2, parcel);
                return new PublisherAdViewOptions(zM2, iBinderN, iBinderN2);
            case EventType.SUBS /* 25 */:
                int iS3 = AbstractC3471i3.s(parcel);
                String strG3 = null;
                String strG4 = null;
                while (parcel.dataPosition() < iS3) {
                    int i4 = parcel.readInt();
                    char c2 = (char) i4;
                    if (c2 == 1) {
                        strG2 = AbstractC3471i3.g(i4, parcel);
                    } else if (c2 == 2) {
                        strG3 = AbstractC3471i3.g(i4, parcel);
                    } else if (c2 != 3) {
                        AbstractC3471i3.r(i4, parcel);
                    } else {
                        strG4 = AbstractC3471i3.g(i4, parcel);
                    }
                }
                AbstractC3471i3.l(iS3, parcel);
                return new zza(strG2, strG3, strG4);
            case EventType.CDN /* 26 */:
                int iS4 = AbstractC3471i3.s(parcel);
                boolean zM3 = false;
                String strG5 = null;
                String strG6 = null;
                String strG7 = null;
                String strG8 = null;
                String strG9 = null;
                String strG10 = null;
                String strG11 = null;
                Intent intent = null;
                IBinder iBinderN3 = null;
                while (parcel.dataPosition() < iS4) {
                    int i5 = parcel.readInt();
                    switch ((char) i5) {
                        case 2:
                            strG5 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 3:
                            strG6 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 4:
                            strG7 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 5:
                            strG8 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 6:
                            strG9 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case 7:
                            strG10 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case '\b':
                            strG11 = AbstractC3471i3.g(i5, parcel);
                            break;
                        case '\t':
                            intent = (Intent) AbstractC3471i3.f(parcel, i5, Intent.CREATOR);
                            break;
                        case '\n':
                            iBinderN3 = AbstractC3471i3.n(i5, parcel);
                            break;
                        case 11:
                            zM3 = AbstractC3471i3.m(i5, parcel);
                            break;
                        default:
                            AbstractC3471i3.r(i5, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS4, parcel);
                return new zzc(strG5, strG6, strG7, strG8, strG9, strG10, strG11, intent, iBinderN3, zM3);
            case 27:
                int iS5 = AbstractC3471i3.s(parcel);
                long jP = 0;
                boolean zM4 = false;
                int iO2 = 0;
                int iO3 = 0;
                boolean zM5 = false;
                zzc zzcVar = null;
                IBinder iBinderN4 = null;
                IBinder iBinderN5 = null;
                IBinder iBinderN6 = null;
                IBinder iBinderN7 = null;
                String strG12 = null;
                String strG13 = null;
                IBinder iBinderN8 = null;
                String strG14 = null;
                VersionInfoParcel versionInfoParcel = null;
                String strG15 = null;
                zzl zzlVar = null;
                IBinder iBinderN9 = null;
                String strG16 = null;
                String strG17 = null;
                String strG18 = null;
                IBinder iBinderN10 = null;
                IBinder iBinderN11 = null;
                IBinder iBinderN12 = null;
                while (parcel.dataPosition() < iS5) {
                    int i6 = parcel.readInt();
                    switch ((char) i6) {
                        case 2:
                            zzcVar = (zzc) AbstractC3471i3.f(parcel, i6, zzc.CREATOR);
                            break;
                        case 3:
                            iBinderN4 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 4:
                            iBinderN5 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 5:
                            iBinderN6 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 6:
                            iBinderN7 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 7:
                            strG12 = AbstractC3471i3.g(i6, parcel);
                            break;
                        case '\b':
                            zM4 = AbstractC3471i3.m(i6, parcel);
                            break;
                        case '\t':
                            strG13 = AbstractC3471i3.g(i6, parcel);
                            break;
                        case '\n':
                            iBinderN8 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 11:
                            iO2 = AbstractC3471i3.o(i6, parcel);
                            break;
                        case '\f':
                            iO3 = AbstractC3471i3.o(i6, parcel);
                            break;
                        case '\r':
                            strG14 = AbstractC3471i3.g(i6, parcel);
                            break;
                        case 14:
                            versionInfoParcel = (VersionInfoParcel) AbstractC3471i3.f(parcel, i6, VersionInfoParcel.CREATOR);
                            break;
                        case 15:
                        case 20:
                        case 21:
                        case EventType.WINDOW_STATE /* 22 */:
                        case EventType.AUDIO /* 23 */:
                        default:
                            AbstractC3471i3.r(i6, parcel);
                            break;
                        case 16:
                            strG15 = AbstractC3471i3.g(i6, parcel);
                            break;
                        case 17:
                            zzlVar = (zzl) AbstractC3471i3.f(parcel, i6, zzl.CREATOR);
                            break;
                        case 18:
                            iBinderN9 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 19:
                            strG16 = AbstractC3471i3.g(i6, parcel);
                            break;
                        case EventType.VIDEO /* 24 */:
                            strG17 = AbstractC3471i3.g(i6, parcel);
                            break;
                        case EventType.SUBS /* 25 */:
                            strG18 = AbstractC3471i3.g(i6, parcel);
                            break;
                        case EventType.CDN /* 26 */:
                            iBinderN10 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 27:
                            iBinderN11 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 28:
                            iBinderN12 = AbstractC3471i3.n(i6, parcel);
                            break;
                        case 29:
                            zM5 = AbstractC3471i3.m(i6, parcel);
                            break;
                        case 30:
                            jP = AbstractC3471i3.p(i6, parcel);
                            break;
                    }
                }
                AbstractC3471i3.l(iS5, parcel);
                return new AdOverlayInfoParcel(zzcVar, iBinderN4, iBinderN5, iBinderN6, iBinderN7, strG12, zM4, strG13, iBinderN8, iO2, iO3, strG14, versionInfoParcel, strG15, zzlVar, iBinderN9, strG16, strG17, strG18, iBinderN10, iBinderN11, iBinderN12, zM5, jP);
            case 28:
                int iS6 = AbstractC3471i3.s(parcel);
                int iO4 = 0;
                int iO5 = 0;
                boolean zM6 = false;
                boolean zM7 = false;
                String strG19 = null;
                while (parcel.dataPosition() < iS6) {
                    int i7 = parcel.readInt();
                    char c3 = (char) i7;
                    if (c3 == 2) {
                        strG19 = AbstractC3471i3.g(i7, parcel);
                    } else if (c3 == 3) {
                        iO4 = AbstractC3471i3.o(i7, parcel);
                    } else if (c3 == 4) {
                        iO5 = AbstractC3471i3.o(i7, parcel);
                    } else if (c3 == 5) {
                        zM6 = AbstractC3471i3.m(i7, parcel);
                    } else if (c3 != 6) {
                        AbstractC3471i3.r(i7, parcel);
                    } else {
                        zM7 = AbstractC3471i3.m(i7, parcel);
                    }
                }
                AbstractC3471i3.l(iS6, parcel);
                return new VersionInfoParcel(strG19, iO4, iO5, zM6, zM7);
            default:
                int iS7 = AbstractC3471i3.s(parcel);
                while (parcel.dataPosition() < iS7) {
                    int i8 = parcel.readInt();
                    char c4 = (char) i8;
                    if (c4 == 1) {
                        strG = AbstractC3471i3.g(i8, parcel);
                    } else if (c4 != 2) {
                        AbstractC3471i3.r(i8, parcel);
                    } else {
                        iO = AbstractC3471i3.o(i8, parcel);
                    }
                }
                AbstractC3471i3.l(iS7, parcel);
                return new zzbb(strG, iO);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new MediaBrowserCompat$MediaItem[i];
            case 1:
                return new MediaDescriptionCompat[i];
            case 2:
                return new MediaMetadataCompat[i];
            case 3:
                return new RatingCompat[i];
            case 4:
                return new ResultReceiver[i];
            case 5:
                return new ActivityResult[i];
            case 6:
                return new IntentSenderRequest[i];
            case 7:
                return new ParcelImpl[i];
            case 8:
                return new JWT[i];
            case 9:
                return new AccessToken[i];
            case 10:
                return new AuthenticationToken[i];
            case 11:
                return new AuthenticationTokenClaims[i];
            case 12:
                return new AuthenticationTokenHeader[i];
            case 13:
                return new FacebookRequestError[i];
            case 14:
                return new GraphRequest$ParcelableResourceWithMimeType[i];
            case 15:
                return new Profile[i];
            case 16:
                return new Format[i];
            case 17:
                return new DrmInitData[i];
            case 18:
                return new Metadata[i];
            case 19:
                return new TrackGroup[i];
            case 20:
                return new TrackGroupArray[i];
            case 21:
                return new DefaultTrackSelector$SelectionOverride[i];
            case EventType.WINDOW_STATE /* 22 */:
                return new ColorInfo[i];
            case EventType.AUDIO /* 23 */:
                return new AdManagerAdViewOptions[i];
            case EventType.VIDEO /* 24 */:
                return new PublisherAdViewOptions[i];
            case EventType.SUBS /* 25 */:
                return new zza[i];
            case EventType.CDN /* 26 */:
                return new zzc[i];
            case 27:
                return new AdOverlayInfoParcel[i];
            case 28:
                return new VersionInfoParcel[i];
            default:
                return new zzbb[i];
        }
    }
}
