//! Form state of the main screens (spec/15 §3.2, §11.3, §11.4 S3): the text of each plain edit,
//! and the credential units captured with one press.
//!
//! Plain edits ([`EditField`]) hold no wallet secret; their text lives in [`FormState`] as
//! `Zeroizing` strings anyway, because the `WalletConnect` pairing link (its `symKey`, spec/15
//! §12.2) and RPC URLs pass through them. The seven masked credential edits ([`CredField`]: RPC
//! tokens, keys and URLs, D13) are never form state: the shell reads them only when a press that
//! uses them happens and hands the units over in a [`PressInput`], wiped on drop (D28).
//!
//! 2026-11-18 (S3 B1): created. S3 mirrors the form state from the Windows edits (`Cmd::Form`
//! at every press and after every render, Windows-transitional); S5 makes it engine-owned.
//!
//! 2026-11-18 (S3 D1): a press also carries what the shell read from the clipboard for it
//! ([`ClipInput`], the `WalletConnect` panel's `클립보드에서 연결` and `클립보드 이미지에서 QR
//! 읽기`); before, the handler read the clipboard itself.
//!
//! 2026-11-20 (S4 P5): the Windows `CF_DIB` bytes ([`ClipInput::WinDib`]) are wiped on drop
//! (before, a plain `Vec`), and the `WalletConnect` panel's `이미지 파일에서 QR 읽기` carries the
//! image file the shell read and decoded with the press ([`ImageInput`]); before, the handler
//! opened and decoded the file itself.

use core::fmt;

use yw_core::secret::Zeroizing;

/// A plain (non-secret, non-credential) edit of the main screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EditField {
    /// The account rename edit of the core screens.
    CoreRename,
    /// Settings › 보안: auto-lock minutes.
    CoreAutoLock,
    /// Address book: address.
    BookAddress,
    /// Address book: label.
    BookLabel,
    /// Address book: the `이 주소 저장` prompt's label.
    BookPromptLabel,
    /// Bitcoin send: recipient.
    BtcSendTo,
    /// Bitcoin send: amount.
    BtcSendAmount,
    /// Bitcoin send: manual fee rate.
    BtcFeeManual,
    /// Bitcoin send: typed confirmation of a high fee.
    BtcTypedFee,
    /// Bitcoin fee bump: manual fee rate.
    BtcBumpManual,
    /// Bitcoin fee bump: typed confirmation of a high fee.
    BtcBumpTyped,
    /// Bitcoin account card: name.
    BtcRename,
    /// Settings › Bitcoin: Esplora URL, mainnet.
    BtcEsploraMainnet,
    /// Settings › Bitcoin: Esplora URL, testnet4.
    BtcEsploraTestnet4,
    /// EVM send: recipient.
    EvmSendTo,
    /// EVM send: amount.
    EvmSendAmount,
    /// EVM token form: contract address.
    EvmTokenAddress,
    /// EVM token form: label.
    EvmTokenLabel,
    /// EVM chain form: chain id.
    EvmChainId,
    /// EVM chain form: name.
    EvmChainName,
    /// EVM chain form: symbol.
    EvmChainSymbol,
    /// EVM chain form: decimals.
    EvmChainDecimals,
    /// EVM chain form: explorer URL.
    EvmChainExplorer,
    /// EVM fee caps: max fee.
    EvmCapFee,
    /// EVM fee caps: max tip.
    EvmCapTip,
    /// EVM fee caps: max total.
    EvmCapTotal,
    /// S15 explorer card: transaction template.
    ExplorerTx,
    /// S15 explorer card: address template.
    ExplorerAddress,
    /// `HyperCore`: recipient.
    HcTo,
    /// `HyperCore`: amount.
    HcAmount,
    /// `HyperCore` settings: testnet API URL.
    HcApi,
    /// AI 설명: endpoint URL.
    LlmEndpoint,
    /// AI 설명: model.
    LlmModel,
    /// AI 설명: max tokens.
    LlmMaxTokens,
    /// Recovery phrases: the typed word that confirms a removal.
    MnRemoveTyped,
    /// Recovery phrases: name.
    MnRename,
    /// S22: the typed reset phrase.
    ResetPhrase,
    /// Solana send: recipient.
    SolSendTo,
    /// Solana send: amount.
    SolSendAmount,
    /// Settings › Solana: fee cap.
    SolFeeCap,
    /// Settings › Solana: compute-unit price.
    SolCuPrice,
    /// Solana account card: name.
    SolRename,
    /// `WalletConnect`: pairing link (holds the pairing `symKey`).
    WcUri,
    /// `WalletConnect`: QR image file path.
    WcFile,
    /// `WalletConnect`: project id.
    WcProject,
    /// `YubiKey` wizard: SIG account index.
    YkSigIndex,
    /// `YubiKey` wizard: AUT account index.
    YkAutIndex,
    /// `YubiKey` wizard: Solana account count.
    YkSolCount,
    /// `YubiKey` wizard: Solana first account.
    YkSolStart,
    /// `YubiKey` wizard: the typed word that confirms an overwrite.
    YkOverwrite,
    /// `YubiKey` card: name.
    YkCardName,
    /// `YubiKey` re-slot: SIG account index.
    YkReslotSigIndex,
    /// `YubiKey` re-slot: AUT account index.
    YkReslotAutIndex,
    /// `YubiKey` clear: the typed confirmation word.
    YkClearConfirm,
    /// `YubiKey` re-slot: the typed loss acknowledgement.
    YkReslotLoss,
    /// `YubiKey` clear: the typed loss acknowledgement.
    YkClearLoss,
    /// Zcash send: recipient.
    ZecSendTo,
    /// Zcash send: amount.
    ZecSendAmount,
}

impl EditField {
    /// Every plain edit.
    pub const ALL: [Self; 58] = [
        Self::CoreRename,
        Self::CoreAutoLock,
        Self::BookAddress,
        Self::BookLabel,
        Self::BookPromptLabel,
        Self::BtcSendTo,
        Self::BtcSendAmount,
        Self::BtcFeeManual,
        Self::BtcTypedFee,
        Self::BtcBumpManual,
        Self::BtcBumpTyped,
        Self::BtcRename,
        Self::BtcEsploraMainnet,
        Self::BtcEsploraTestnet4,
        Self::EvmSendTo,
        Self::EvmSendAmount,
        Self::EvmTokenAddress,
        Self::EvmTokenLabel,
        Self::EvmChainId,
        Self::EvmChainName,
        Self::EvmChainSymbol,
        Self::EvmChainDecimals,
        Self::EvmChainExplorer,
        Self::EvmCapFee,
        Self::EvmCapTip,
        Self::EvmCapTotal,
        Self::ExplorerTx,
        Self::ExplorerAddress,
        Self::HcTo,
        Self::HcAmount,
        Self::HcApi,
        Self::LlmEndpoint,
        Self::LlmModel,
        Self::LlmMaxTokens,
        Self::MnRemoveTyped,
        Self::MnRename,
        Self::ResetPhrase,
        Self::SolSendTo,
        Self::SolSendAmount,
        Self::SolFeeCap,
        Self::SolCuPrice,
        Self::SolRename,
        Self::WcUri,
        Self::WcFile,
        Self::WcProject,
        Self::YkSigIndex,
        Self::YkAutIndex,
        Self::YkSolCount,
        Self::YkSolStart,
        Self::YkOverwrite,
        Self::YkCardName,
        Self::YkReslotSigIndex,
        Self::YkReslotAutIndex,
        Self::YkClearConfirm,
        Self::YkReslotLoss,
        Self::YkClearLoss,
        Self::ZecSendTo,
        Self::ZecSendAmount,
    ];

    /// Read cap in UTF-16 units: the one cap the Windows app reads the field with (2026-11-18:
    /// yw-app's read sites each pass this literal or their module's `TEXT_MAX`).
    #[must_use]
    pub const fn cap(self) -> usize {
        match self {
            Self::CoreAutoLock
            | Self::LlmMaxTokens
            | Self::YkSigIndex
            | Self::YkAutIndex
            | Self::YkSolCount
            | Self::YkSolStart => 8,
            Self::YkOverwrite
            | Self::YkReslotSigIndex
            | Self::YkReslotAutIndex
            | Self::YkClearConfirm
            | Self::YkReslotLoss
            | Self::YkClearLoss => 16,
            Self::MnRemoveTyped | Self::ResetPhrase => 32,
            Self::CoreRename
            | Self::BtcRename
            | Self::MnRename
            | Self::WcProject
            | Self::YkCardName => 64,
            Self::LlmModel => 128,
            Self::SolSendTo
            | Self::SolSendAmount
            | Self::SolFeeCap
            | Self::SolCuPrice
            | Self::SolRename => 256,
            Self::BookAddress
            | Self::BookLabel
            | Self::BookPromptLabel
            | Self::BtcSendTo
            | Self::BtcSendAmount
            | Self::BtcFeeManual
            | Self::BtcTypedFee
            | Self::BtcBumpManual
            | Self::BtcBumpTyped
            | Self::BtcEsploraMainnet
            | Self::BtcEsploraTestnet4
            | Self::EvmSendTo
            | Self::EvmSendAmount
            | Self::EvmTokenAddress
            | Self::EvmTokenLabel
            | Self::EvmChainId
            | Self::EvmChainName
            | Self::EvmChainSymbol
            | Self::EvmChainDecimals
            | Self::EvmChainExplorer
            | Self::EvmCapFee
            | Self::EvmCapTip
            | Self::EvmCapTotal
            | Self::ExplorerTx
            | Self::ExplorerAddress
            | Self::HcTo
            | Self::HcAmount
            | Self::HcApi => 512,
            Self::WcFile | Self::ZecSendTo | Self::ZecSendAmount => 1_024,
            Self::WcUri | Self::LlmEndpoint => 2_048,
        }
    }

    /// `text` cut to [`cap`](Self::cap) UTF-16 units and decoded like the Windows edit read
    /// (`String::from_utf16_lossy` of the first `cap()` units: a surrogate pair split by the cut
    /// becomes U+FFFD), so a value is the same whether the shell or the logic cut it. No
    /// intermediate buffer outlives the call unwiped.
    #[must_use]
    pub fn clamp(self, text: &str) -> Zeroizing<String> {
        let cap = self.cap();
        let mut units = Zeroizing::new(Vec::with_capacity(text.len().min(cap)));
        units.extend(text.encode_utf16().take(cap));
        // A UTF-16 unit decodes to at most 3 UTF-8 bytes (U+FFFD for a lone surrogate), so the
        // string never reallocates and leaves no copy behind.
        let mut out = Zeroizing::new(String::with_capacity(units.len().saturating_mul(3)));
        out.extend(
            char::decode_utf16(units.iter().copied())
                .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER)),
        );
        out
    }
}

/// The seven masked credential edits (RPC tokens, keys and URLs; D13). Never in [`FormState`],
/// `Cmd::Edit`, [`FormSnapshot`] or an `Effect` payload (D28).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredField {
    /// Settings › 네트워크: `QuickNode` endpoint name.
    QnName,
    /// Settings › 네트워크: `QuickNode` token.
    QnToken,
    /// Settings › 네트워크: Alchemy key.
    AlchemyKey,
    /// Settings › 네트워크: a network's replacement RPC URL (`교체`).
    RpcReplace,
    /// S08 처음 설정: `QuickNode` endpoint URL.
    DoneQn,
    /// EVM chain form: RPC URL.
    ChainRpc,
    /// AI 설명: API key.
    LlmKey,
}

impl CredField {
    /// Every credential edit.
    pub const ALL: [Self; 7] = [
        Self::QnName,
        Self::QnToken,
        Self::AlchemyKey,
        Self::RpcReplace,
        Self::DoneQn,
        Self::ChainRpc,
        Self::LlmKey,
    ];

    /// Read cap in UTF-16 units (yw-app `TOKEN_MAX_UNITS` 256, `URL_MAX_UNITS` 2 048, the chain
    /// form's RPC 2 048 and the LLM key 1 024).
    #[must_use]
    pub const fn cap(self) -> usize {
        match self {
            Self::QnName | Self::QnToken | Self::AlchemyKey | Self::DoneQn => 256,
            Self::LlmKey => 1_024,
            Self::RpcReplace | Self::ChainRpc => 2_048,
        }
    }
}

/// What the plain edits show (Windows-transitional `Cmd::Form`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FormSnapshot(pub Vec<(EditField, Zeroizing<String>)>);

/// Field names and lengths only.
impl fmt::Debug for FormSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FormSnapshot")
            .field(&Lengths(&self.0))
            .finish()
    }
}

/// `{field: len, …}` of a field list.
struct Lengths<'a>(&'a [(EditField, Zeroizing<String>)]);

impl fmt::Debug for Lengths<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_map()
            .entries(self.0.iter().map(|(field, text)| (field, text.len())))
            .finish()
    }
}

/// The text of each plain edit on screen. `None` = no such edit (as the Windows read of a
/// missing control), so every caller's fallback keeps its meaning. S3: mirrored from the shell;
/// S5: owned here (Android sends only `Cmd::Edit`).
#[derive(Default)]
pub struct FormState {
    fields: Vec<(EditField, Zeroizing<String>)>,
}

impl FormState {
    /// Takes a whole snapshot (the edits not in it no longer exist).
    pub fn replace(&mut self, snapshot: FormSnapshot) {
        self.fields = snapshot.0;
    }

    /// Sets one field; `None` removes it.
    pub fn set(&mut self, field: EditField, text: Option<Zeroizing<String>>) {
        let at = self.fields.iter().position(|(known, _)| *known == field);
        match (at, text) {
            (Some(at), Some(text)) => {
                if let Some(slot) = self.fields.get_mut(at) {
                    slot.1 = text;
                }
            }
            (Some(at), None) => {
                self.fields.remove(at);
            }
            (None, Some(text)) => self.fields.push((field, text)),
            (None, None) => {}
        }
    }

    /// The field's text, `None` when the edit does not exist.
    #[must_use]
    pub fn text(&self, field: EditField) -> Option<&str> {
        self.fields
            .iter()
            .find(|(known, _)| *known == field)
            .map(|(_, text)| text.as_str())
    }
}

/// Field names and lengths only.
impl fmt::Debug for FormState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FormState")
            .field("fields", &Lengths(&self.fields))
            .finish()
    }
}

/// One credential field listed for a press.
pub enum CredUnits {
    /// Its edit did not exist when the press happened (reads as empty).
    Absent,
    /// The UTF-16 units it held.
    Units(Zeroizing<Vec<u16>>),
}

/// The unit count only.
impl fmt::Debug for CredUnits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Units(units) => formatter.debug_tuple("Units").field(&units.len()).finish(),
        }
    }
}

/// What the shell read from the clipboard for a press that pairs from it (2026-11-18, S3 D1:
/// spec/13 §6; before, the `WalletConnect` handler read the clipboard itself). Read only when
/// such a press happens, never written.
pub enum ClipInput {
    /// No main window (nothing is read; the press does nothing, as before).
    NoWindow,
    /// A pairing link (`wc:`, or a wholly percent-encoded `wc%3A…`) copied as text. It holds the
    /// pairing `symKey` (spec/15 §12.2), so it is wiped with the press input. Other clipboard
    /// text never becomes a `String`: the shell checks the start on the UTF-16 units.
    Link(Zeroizing<String>),
    /// Windows `CF_DIB` bytes (a Win+Shift+S capture), parsed by
    /// `walletconnect::qr_decode::dib_to_bgra`. Windows only: Android pairs through the
    /// prefilled link and the camera reader (spec/15 §12.2), not this input. Wiped on drop
    /// (2026-11-20, S4 P5: the image may show a pairing QR, whose link holds the `symKey`; the
    /// shell moves `read_dib`'s buffer in without a copy. Before, a plain `Vec`, as `read_dib`
    /// returned it). 2026-11-20 (S4 P5 review): what stays unwiped is recorded as a later item
    /// (spec/13 §6): the QR decoder's grayscale copy of the pixels (`qr_decode::Gray`) and the
    /// decoded link text (`decode_bgra_text`'s `String` and `wc_pair`'s trimmed copy) are plain
    /// buffers, so after a QR press the image as luma and the link still sit in freed memory
    /// unwiped, as before P5. The BGRA pixels `dib_to_bgra` makes are wiped on every path.
    /// 2026-11-21 (S4 F15, spec/15 §18 item 15): that item is done: `Gray`'s luma, the decoded
    /// text and `wc_pair`'s trimmed copy are `Zeroizing`. Still plain: the decoder's inner
    /// buffers (binarised images, sampled grid, codewords, segments; spec/13 §6).
    WinDib(Zeroizing<Vec<u8>>),
    /// The clipboard holds no image.
    NoImage,
    /// The clipboard could not be opened.
    OpenFailed,
}

/// The variant and a length only (the link is the pairing secret).
impl fmt::Debug for ClipInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWindow => formatter.write_str("NoWindow"),
            Self::Link(text) => formatter.debug_tuple("Link").field(&text.len()).finish(),
            Self::WinDib(bytes) => formatter.debug_tuple("WinDib").field(&bytes.len()).finish(),
            Self::NoImage => formatter.write_str("NoImage"),
            Self::OpenFailed => formatter.write_str("OpenFailed"),
        }
    }
}

/// What the shell read for the `WalletConnect` panel's `이미지 파일에서 QR 읽기` (2026-11-20, S4
/// P5: spec/13 §6; before, the handler opened and decoded the file itself): the path is the
/// panel's path field at the press (a quoted path from Explorer's `경로로 복사` is accepted).
/// Only a regular file of at most 64 MB that starts like a PNG, JPEG, BMP or GIF file is handed
/// to the platform decoder (Windows: GDI+). Read only when that press happens, never written.
pub enum ImageInput {
    /// The path field is empty (after trimming spaces and quotes).
    NoPath,
    /// Not an acceptable image file (missing, not a regular file, too large, or another
    /// signature); nothing was handed to the decoder.
    Refused,
    /// The decoder could not read the file.
    Unreadable,
    /// The decoded image: `width × height` pixels, 4 bytes each in B, G, R, A order, top row
    /// first. Wiped on drop (it may show a pairing QR). 2026-11-20 (S4 P5 review): the QR
    /// decoder's grayscale copy and the decoded link text are not wiped yet (a later item,
    /// spec/13 §6; see [`ClipInput::WinDib`]).
    Pixels {
        /// Width in pixels.
        width: usize,
        /// Height in pixels.
        height: usize,
        /// `width * height * 4` bytes.
        pixels: Zeroizing<Vec<u8>>,
    },
}

/// The variant and, for pixels, the size and byte length only.
impl fmt::Debug for ImageInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPath => formatter.write_str("NoPath"),
            Self::Refused => formatter.write_str("Refused"),
            Self::Unreadable => formatter.write_str("Unreadable"),
            Self::Pixels {
                width,
                height,
                pixels,
            } => formatter
                .debug_tuple("Pixels")
                .field(width)
                .field(height)
                .field(&pixels.len())
                .finish(),
        }
    }
}

/// Platform input captured with one press: the units of every credential field the press uses
/// (each listed field has an entry, `Absent` when its edit did not exist) and, for a press that
/// reads the clipboard, what it held (S3 D1), or, for the image-file press, the decoded image (S4
/// P5). No `Clone`; the credential units, a pairing link, a `WinDib` image and the decoded pixels
/// are wiped on drop (2026-11-20, S4 P5: before, a `WinDib` image was not).
#[derive(Default)]
pub struct PressInput {
    creds: Vec<(CredField, CredUnits)>,
    clip: Option<ClipInput>,
    image: Option<ImageInput>,
    /// Debug builds only (plan §2.3, §3.2a): release builds compile no checking code.
    #[cfg(debug_assertions)]
    misses: u32,
}

impl PressInput {
    /// The input of a press that uses `creds`.
    #[must_use]
    pub const fn new(creds: Vec<(CredField, CredUnits)>) -> Self {
        Self {
            creds,
            clip: None,
            image: None,
            #[cfg(debug_assertions)]
            misses: 0,
        }
    }

    /// The same input with what the clipboard held at the press (S3 D1).
    #[must_use]
    pub fn with_clip(mut self, clip: ClipInput) -> Self {
        self.clip = Some(clip);
        self
    }

    /// Moves the clipboard input out. `None` when the press captured none (a table bug, or a
    /// second take); debug builds count it in `misses`, like a credential take with no entry.
    pub fn take_clip(&mut self) -> Option<ClipInput> {
        let clip = self.clip.take();
        #[cfg(debug_assertions)]
        if clip.is_none() {
            self.misses = self.misses.saturating_add(1);
        }
        clip
    }

    /// The same input with the image file the shell read for the press (S4 P5).
    #[must_use]
    pub fn with_image(mut self, image: ImageInput) -> Self {
        self.image = Some(image);
        self
    }

    /// Moves the image input out. `None` when the press captured none (a table bug, or a second
    /// take); debug builds count it in `misses`, like [`PressInput::take_clip`].
    pub fn take_image(&mut self) -> Option<ImageInput> {
        let image = self.image.take();
        #[cfg(debug_assertions)]
        if image.is_none() {
            self.misses = self.misses.saturating_add(1);
        }
        image
    }

    /// Moves the units of `field` out: empty for `Absent` or a second take, as the Windows read
    /// of a missing edit. A field with no entry (not captured for this press: a table bug) also
    /// gives empty units; debug builds count it in `misses`.
    pub fn take(&mut self, field: CredField) -> Zeroizing<Vec<u16>> {
        let Some((_, units)) = self.creds.iter_mut().find(|(known, _)| *known == field) else {
            #[cfg(debug_assertions)]
            {
                self.misses = self.misses.saturating_add(1);
            }
            return Zeroizing::new(Vec::new());
        };
        match core::mem::replace(units, CredUnits::Absent) {
            CredUnits::Absent => Zeroizing::new(Vec::new()),
            CredUnits::Units(units) => units,
        }
    }

    /// Takes of a field with no entry so far (tests assert 0). Debug builds only.
    #[cfg(debug_assertions)]
    #[must_use]
    pub const fn misses(&self) -> u32 {
        self.misses
    }
}

/// Field names and unit counts only (the clipboard input, when there is one, its variant and
/// length; the image input its variant, size and length).
impl fmt::Debug for PressInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut shown = formatter.debug_struct("PressInput");
        shown.field("creds", &self.creds);
        if let Some(clip) = &self.clip {
            shown.field("clip", clip);
        }
        if let Some(image) = &self.image {
            shown.field("image", image);
        }
        #[cfg(debug_assertions)]
        shown.field("misses", &self.misses);
        shown.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Zeroizing<Vec<u16>> {
        Zeroizing::new(text.encode_utf16().collect())
    }

    #[test]
    fn edit_fields_are_unique_and_capped() {
        for (at, field) in EditField::ALL.iter().enumerate() {
            assert!(
                !EditField::ALL[..at].contains(field),
                "{field:?} listed twice"
            );
            assert!(field.cap() >= 8, "{field:?}");
        }
        for (at, field) in CredField::ALL.iter().enumerate() {
            assert!(
                !CredField::ALL[..at].contains(field),
                "{field:?} listed twice"
            );
        }
    }

    #[test]
    fn clamp_cuts_at_the_cap_like_the_window_read() {
        let long = "a".repeat(40);
        assert_eq!(EditField::ResetPhrase.clamp(&long).as_str(), "a".repeat(32));
        assert_eq!(EditField::ResetPhrase.clamp("short").as_str(), "short");
        assert_eq!(EditField::CoreAutoLock.clamp("").as_str(), "");
        // 7 ASCII units then a surrogate pair cut after its first half (cap 8).
        let split = "1234567\u{1F600}";
        let expect = String::from_utf16_lossy(&split.encode_utf16().take(8).collect::<Vec<_>>());
        assert_eq!(EditField::CoreAutoLock.clamp(split).as_str(), expect);
        assert_eq!(expect, "1234567\u{FFFD}");
        // A whole pair inside the cap stays.
        assert_eq!(
            EditField::CoreAutoLock.clamp("123456\u{1F600}").as_str(),
            "123456\u{1F600}"
        );
        // Hangul (one unit, three UTF-8 bytes each) at the cap.
        let hangul = "가".repeat(10);
        assert_eq!(
            EditField::CoreAutoLock.clamp(&hangul).as_str(),
            "가".repeat(8)
        );
    }

    #[test]
    fn form_state_knows_presence() {
        let mut state = FormState::default();
        assert_eq!(state.text(EditField::EvmSendTo), None);
        state.set(EditField::EvmSendTo, Some(Zeroizing::new(String::new())));
        assert_eq!(state.text(EditField::EvmSendTo), Some(""));
        state.set(EditField::EvmSendTo, Some(Zeroizing::new("x".to_owned())));
        assert_eq!(state.text(EditField::EvmSendTo), Some("x"));
        state.set(EditField::EvmSendTo, None);
        assert_eq!(state.text(EditField::EvmSendTo), None);
        state.set(EditField::EvmSendTo, None);
        assert_eq!(state.text(EditField::EvmSendTo), None);
        state.set(EditField::HcTo, Some(Zeroizing::new("y".to_owned())));
        state.replace(FormSnapshot(vec![(
            EditField::SolSendTo,
            Zeroizing::new("z".to_owned()),
        )]));
        assert_eq!(state.text(EditField::HcTo), None);
        assert_eq!(state.text(EditField::SolSendTo), Some("z"));
        let shown = format!("{state:?}");
        assert_eq!(shown, "FormState { fields: {SolSendTo: 1} }");
    }

    #[test]
    fn take_moves_units_out_once() {
        let mut input = PressInput::new(vec![
            (CredField::QnName, CredUnits::Units(units("name"))),
            (CredField::QnToken, CredUnits::Absent),
        ]);
        assert_eq!(
            input.take(CredField::QnName).as_slice(),
            units("name").as_slice()
        );
        assert!(input.take(CredField::QnName).is_empty());
        assert!(input.take(CredField::QnToken).is_empty());
        #[cfg(debug_assertions)]
        assert_eq!(input.misses(), 0);
        assert!(input.take(CredField::LlmKey).is_empty());
        #[cfg(debug_assertions)]
        assert_eq!(input.misses(), 1);
        assert!(PressInput::default().take(CredField::DoneQn).is_empty());
        let shown = format!("{input:?}");
        #[cfg(debug_assertions)]
        assert_eq!(
            shown,
            "PressInput { creds: [(QnName, Absent), (QnToken, Absent)], misses: 1 }"
        );
        #[cfg(not(debug_assertions))]
        assert_eq!(
            shown,
            "PressInput { creds: [(QnName, Absent), (QnToken, Absent)] }"
        );
    }

    #[test]
    fn clip_input_is_taken_once_and_prints_no_text() {
        let mut input = PressInput::default().with_clip(ClipInput::Link(Zeroizing::new(
            "wc:topic@2?symKey=ab".to_owned(),
        )));
        let shown = format!("{input:?}");
        assert!(!shown.contains("symKey"), "{shown}");
        assert!(shown.contains("clip: Link(20)"), "{shown}");
        assert!(
            matches!(input.take_clip(), Some(ClipInput::Link(text)) if text.starts_with("wc:"))
        );
        #[cfg(debug_assertions)]
        assert_eq!(input.misses(), 0);
        assert!(input.take_clip().is_none());
        #[cfg(debug_assertions)]
        assert_eq!(input.misses(), 1);
        assert_eq!(
            format!("{:?}", ClipInput::WinDib(Zeroizing::new(vec![0; 40]))),
            "WinDib(40)"
        );
        for (clip, shown) in [
            (ClipInput::NoWindow, "NoWindow"),
            (ClipInput::NoImage, "NoImage"),
            (ClipInput::OpenFailed, "OpenFailed"),
        ] {
            assert_eq!(format!("{clip:?}"), shown);
        }
    }

    /// S4 P5: the image input is taken once (a second take is a debug miss) and prints its size
    /// and length only; a press input with no image prints no `image` field.
    #[test]
    fn image_input_is_taken_once_and_prints_no_pixels() {
        let mut input = PressInput::default().with_image(ImageInput::Pixels {
            width: 3,
            height: 2,
            pixels: Zeroizing::new(vec![0x7F; 24]),
        });
        let shown = format!("{input:?}");
        assert!(shown.contains("image: Pixels(3, 2, 24)"), "{shown}");
        assert!(!shown.contains("127"), "{shown}");
        assert!(matches!(
            input.take_image(),
            Some(ImageInput::Pixels { width: 3, height: 2, pixels }) if pixels.len() == 24
        ));
        #[cfg(debug_assertions)]
        assert_eq!(input.misses(), 0);
        assert!(input.take_image().is_none());
        #[cfg(debug_assertions)]
        assert_eq!(input.misses(), 1);
        assert!(!format!("{input:?}").contains("image"));
        for (image, shown) in [
            (ImageInput::NoPath, "NoPath"),
            (ImageInput::Refused, "Refused"),
            (ImageInput::Unreadable, "Unreadable"),
        ] {
            assert_eq!(format!("{image:?}"), shown);
        }
    }

    #[test]
    fn debug_prints_no_text() {
        let snapshot = FormSnapshot(vec![(
            EditField::WcUri,
            Zeroizing::new("wc:topic@2?symKey=ab".to_owned()),
        )]);
        let shown = format!("{snapshot:?}");
        assert!(!shown.contains("symKey"), "{shown}");
        let input = PressInput::new(vec![(
            CredField::LlmKey,
            CredUnits::Units(units("key-secret")),
        )]);
        let shown = format!("{input:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("Units(10)"), "{shown}");
    }
}
