// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: sdc_internal.proto

#ifndef PROTOBUF_sdc_5finternal_2eproto__INCLUDED
#define PROTOBUF_sdc_5finternal_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2005000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2005000 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/unknown_field_set.h>
#include "draios.pb.h"
// @@protoc_insertion_point(includes)

namespace sdc_internal {

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_sdc_5finternal_2eproto();
void protobuf_AssignDesc_sdc_5finternal_2eproto();
void protobuf_ShutdownFile_sdc_5finternal_2eproto();

class container_mounts;
class mounted_fs_response;
class container_info;
class mounted_fs_request;

// ===================================================================

class container_mounts : public ::google::protobuf::Message {
 public:
  container_mounts();
  virtual ~container_mounts();

  container_mounts(const container_mounts& from);

  inline container_mounts& operator=(const container_mounts& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const container_mounts& default_instance();

  void Swap(container_mounts* other);

  // implements Message ----------------------------------------------

  container_mounts* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const container_mounts& from);
  void MergeFrom(const container_mounts& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required string container_id = 1;
  inline bool has_container_id() const;
  inline void clear_container_id();
  static const int kContainerIdFieldNumber = 1;
  inline const ::std::string& container_id() const;
  inline void set_container_id(const ::std::string& value);
  inline void set_container_id(const char* value);
  inline void set_container_id(const char* value, size_t size);
  inline ::std::string* mutable_container_id();
  inline ::std::string* release_container_id();
  inline void set_allocated_container_id(::std::string* container_id);

  // repeated .draiosproto.mounted_fs mounts = 2;
  inline int mounts_size() const;
  inline void clear_mounts();
  static const int kMountsFieldNumber = 2;
  inline const ::draiosproto::mounted_fs& mounts(int index) const;
  inline ::draiosproto::mounted_fs* mutable_mounts(int index);
  inline ::draiosproto::mounted_fs* add_mounts();
  inline const ::google::protobuf::RepeatedPtrField< ::draiosproto::mounted_fs >&
      mounts() const;
  inline ::google::protobuf::RepeatedPtrField< ::draiosproto::mounted_fs >*
      mutable_mounts();

  // @@protoc_insertion_point(class_scope:sdc_internal.container_mounts)
 private:
  inline void set_has_container_id();
  inline void clear_has_container_id();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::std::string* container_id_;
  ::google::protobuf::RepeatedPtrField< ::draiosproto::mounted_fs > mounts_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(2 + 31) / 32];

  friend void  protobuf_AddDesc_sdc_5finternal_2eproto();
  friend void protobuf_AssignDesc_sdc_5finternal_2eproto();
  friend void protobuf_ShutdownFile_sdc_5finternal_2eproto();

  void InitAsDefaultInstance();
  static container_mounts* default_instance_;
};
// -------------------------------------------------------------------

class mounted_fs_response : public ::google::protobuf::Message {
 public:
  mounted_fs_response();
  virtual ~mounted_fs_response();

  mounted_fs_response(const mounted_fs_response& from);

  inline mounted_fs_response& operator=(const mounted_fs_response& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const mounted_fs_response& default_instance();

  void Swap(mounted_fs_response* other);

  // implements Message ----------------------------------------------

  mounted_fs_response* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const mounted_fs_response& from);
  void MergeFrom(const mounted_fs_response& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // repeated .sdc_internal.container_mounts containers = 1;
  inline int containers_size() const;
  inline void clear_containers();
  static const int kContainersFieldNumber = 1;
  inline const ::sdc_internal::container_mounts& containers(int index) const;
  inline ::sdc_internal::container_mounts* mutable_containers(int index);
  inline ::sdc_internal::container_mounts* add_containers();
  inline const ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_mounts >&
      containers() const;
  inline ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_mounts >*
      mutable_containers();

  // @@protoc_insertion_point(class_scope:sdc_internal.mounted_fs_response)
 private:

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_mounts > containers_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(1 + 31) / 32];

  friend void  protobuf_AddDesc_sdc_5finternal_2eproto();
  friend void protobuf_AssignDesc_sdc_5finternal_2eproto();
  friend void protobuf_ShutdownFile_sdc_5finternal_2eproto();

  void InitAsDefaultInstance();
  static mounted_fs_response* default_instance_;
};
// -------------------------------------------------------------------

class container_info : public ::google::protobuf::Message {
 public:
  container_info();
  virtual ~container_info();

  container_info(const container_info& from);

  inline container_info& operator=(const container_info& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const container_info& default_instance();

  void Swap(container_info* other);

  // implements Message ----------------------------------------------

  container_info* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const container_info& from);
  void MergeFrom(const container_info& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required string id = 1;
  inline bool has_id() const;
  inline void clear_id();
  static const int kIdFieldNumber = 1;
  inline const ::std::string& id() const;
  inline void set_id(const ::std::string& value);
  inline void set_id(const char* value);
  inline void set_id(const char* value, size_t size);
  inline ::std::string* mutable_id();
  inline ::std::string* release_id();
  inline void set_allocated_id(::std::string* id);

  // required uint64 pid = 2;
  inline bool has_pid() const;
  inline void clear_pid();
  static const int kPidFieldNumber = 2;
  inline ::google::protobuf::uint64 pid() const;
  inline void set_pid(::google::protobuf::uint64 value);

  // required uint64 vpid = 3;
  inline bool has_vpid() const;
  inline void clear_vpid();
  static const int kVpidFieldNumber = 3;
  inline ::google::protobuf::uint64 vpid() const;
  inline void set_vpid(::google::protobuf::uint64 value);

  // required string root = 4;
  inline bool has_root() const;
  inline void clear_root();
  static const int kRootFieldNumber = 4;
  inline const ::std::string& root() const;
  inline void set_root(const ::std::string& value);
  inline void set_root(const char* value);
  inline void set_root(const char* value, size_t size);
  inline ::std::string* mutable_root();
  inline ::std::string* release_root();
  inline void set_allocated_root(::std::string* root);

  // @@protoc_insertion_point(class_scope:sdc_internal.container_info)
 private:
  inline void set_has_id();
  inline void clear_has_id();
  inline void set_has_pid();
  inline void clear_has_pid();
  inline void set_has_vpid();
  inline void clear_has_vpid();
  inline void set_has_root();
  inline void clear_has_root();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::std::string* id_;
  ::google::protobuf::uint64 pid_;
  ::google::protobuf::uint64 vpid_;
  ::std::string* root_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(4 + 31) / 32];

  friend void  protobuf_AddDesc_sdc_5finternal_2eproto();
  friend void protobuf_AssignDesc_sdc_5finternal_2eproto();
  friend void protobuf_ShutdownFile_sdc_5finternal_2eproto();

  void InitAsDefaultInstance();
  static container_info* default_instance_;
};
// -------------------------------------------------------------------

class mounted_fs_request : public ::google::protobuf::Message {
 public:
  mounted_fs_request();
  virtual ~mounted_fs_request();

  mounted_fs_request(const mounted_fs_request& from);

  inline mounted_fs_request& operator=(const mounted_fs_request& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const mounted_fs_request& default_instance();

  void Swap(mounted_fs_request* other);

  // implements Message ----------------------------------------------

  mounted_fs_request* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const mounted_fs_request& from);
  void MergeFrom(const mounted_fs_request& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // repeated .sdc_internal.container_info containers = 1;
  inline int containers_size() const;
  inline void clear_containers();
  static const int kContainersFieldNumber = 1;
  inline const ::sdc_internal::container_info& containers(int index) const;
  inline ::sdc_internal::container_info* mutable_containers(int index);
  inline ::sdc_internal::container_info* add_containers();
  inline const ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_info >&
      containers() const;
  inline ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_info >*
      mutable_containers();

  // @@protoc_insertion_point(class_scope:sdc_internal.mounted_fs_request)
 private:

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_info > containers_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(1 + 31) / 32];

  friend void  protobuf_AddDesc_sdc_5finternal_2eproto();
  friend void protobuf_AssignDesc_sdc_5finternal_2eproto();
  friend void protobuf_ShutdownFile_sdc_5finternal_2eproto();

  void InitAsDefaultInstance();
  static mounted_fs_request* default_instance_;
};
// ===================================================================


// ===================================================================

// container_mounts

// required string container_id = 1;
inline bool container_mounts::has_container_id() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void container_mounts::set_has_container_id() {
  _has_bits_[0] |= 0x00000001u;
}
inline void container_mounts::clear_has_container_id() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void container_mounts::clear_container_id() {
  if (container_id_ != &::google::protobuf::internal::kEmptyString) {
    container_id_->clear();
  }
  clear_has_container_id();
}
inline const ::std::string& container_mounts::container_id() const {
  return *container_id_;
}
inline void container_mounts::set_container_id(const ::std::string& value) {
  set_has_container_id();
  if (container_id_ == &::google::protobuf::internal::kEmptyString) {
    container_id_ = new ::std::string;
  }
  container_id_->assign(value);
}
inline void container_mounts::set_container_id(const char* value) {
  set_has_container_id();
  if (container_id_ == &::google::protobuf::internal::kEmptyString) {
    container_id_ = new ::std::string;
  }
  container_id_->assign(value);
}
inline void container_mounts::set_container_id(const char* value, size_t size) {
  set_has_container_id();
  if (container_id_ == &::google::protobuf::internal::kEmptyString) {
    container_id_ = new ::std::string;
  }
  container_id_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* container_mounts::mutable_container_id() {
  set_has_container_id();
  if (container_id_ == &::google::protobuf::internal::kEmptyString) {
    container_id_ = new ::std::string;
  }
  return container_id_;
}
inline ::std::string* container_mounts::release_container_id() {
  clear_has_container_id();
  if (container_id_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = container_id_;
    container_id_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}
inline void container_mounts::set_allocated_container_id(::std::string* container_id) {
  if (container_id_ != &::google::protobuf::internal::kEmptyString) {
    delete container_id_;
  }
  if (container_id) {
    set_has_container_id();
    container_id_ = container_id;
  } else {
    clear_has_container_id();
    container_id_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  }
}

// repeated .draiosproto.mounted_fs mounts = 2;
inline int container_mounts::mounts_size() const {
  return mounts_.size();
}
inline void container_mounts::clear_mounts() {
  mounts_.Clear();
}
inline const ::draiosproto::mounted_fs& container_mounts::mounts(int index) const {
  return mounts_.Get(index);
}
inline ::draiosproto::mounted_fs* container_mounts::mutable_mounts(int index) {
  return mounts_.Mutable(index);
}
inline ::draiosproto::mounted_fs* container_mounts::add_mounts() {
  return mounts_.Add();
}
inline const ::google::protobuf::RepeatedPtrField< ::draiosproto::mounted_fs >&
container_mounts::mounts() const {
  return mounts_;
}
inline ::google::protobuf::RepeatedPtrField< ::draiosproto::mounted_fs >*
container_mounts::mutable_mounts() {
  return &mounts_;
}

// -------------------------------------------------------------------

// mounted_fs_response

// repeated .sdc_internal.container_mounts containers = 1;
inline int mounted_fs_response::containers_size() const {
  return containers_.size();
}
inline void mounted_fs_response::clear_containers() {
  containers_.Clear();
}
inline const ::sdc_internal::container_mounts& mounted_fs_response::containers(int index) const {
  return containers_.Get(index);
}
inline ::sdc_internal::container_mounts* mounted_fs_response::mutable_containers(int index) {
  return containers_.Mutable(index);
}
inline ::sdc_internal::container_mounts* mounted_fs_response::add_containers() {
  return containers_.Add();
}
inline const ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_mounts >&
mounted_fs_response::containers() const {
  return containers_;
}
inline ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_mounts >*
mounted_fs_response::mutable_containers() {
  return &containers_;
}

// -------------------------------------------------------------------

// container_info

// required string id = 1;
inline bool container_info::has_id() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void container_info::set_has_id() {
  _has_bits_[0] |= 0x00000001u;
}
inline void container_info::clear_has_id() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void container_info::clear_id() {
  if (id_ != &::google::protobuf::internal::kEmptyString) {
    id_->clear();
  }
  clear_has_id();
}
inline const ::std::string& container_info::id() const {
  return *id_;
}
inline void container_info::set_id(const ::std::string& value) {
  set_has_id();
  if (id_ == &::google::protobuf::internal::kEmptyString) {
    id_ = new ::std::string;
  }
  id_->assign(value);
}
inline void container_info::set_id(const char* value) {
  set_has_id();
  if (id_ == &::google::protobuf::internal::kEmptyString) {
    id_ = new ::std::string;
  }
  id_->assign(value);
}
inline void container_info::set_id(const char* value, size_t size) {
  set_has_id();
  if (id_ == &::google::protobuf::internal::kEmptyString) {
    id_ = new ::std::string;
  }
  id_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* container_info::mutable_id() {
  set_has_id();
  if (id_ == &::google::protobuf::internal::kEmptyString) {
    id_ = new ::std::string;
  }
  return id_;
}
inline ::std::string* container_info::release_id() {
  clear_has_id();
  if (id_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = id_;
    id_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}
inline void container_info::set_allocated_id(::std::string* id) {
  if (id_ != &::google::protobuf::internal::kEmptyString) {
    delete id_;
  }
  if (id) {
    set_has_id();
    id_ = id;
  } else {
    clear_has_id();
    id_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  }
}

// required uint64 pid = 2;
inline bool container_info::has_pid() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void container_info::set_has_pid() {
  _has_bits_[0] |= 0x00000002u;
}
inline void container_info::clear_has_pid() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void container_info::clear_pid() {
  pid_ = GOOGLE_ULONGLONG(0);
  clear_has_pid();
}
inline ::google::protobuf::uint64 container_info::pid() const {
  return pid_;
}
inline void container_info::set_pid(::google::protobuf::uint64 value) {
  set_has_pid();
  pid_ = value;
}

// required uint64 vpid = 3;
inline bool container_info::has_vpid() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void container_info::set_has_vpid() {
  _has_bits_[0] |= 0x00000004u;
}
inline void container_info::clear_has_vpid() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void container_info::clear_vpid() {
  vpid_ = GOOGLE_ULONGLONG(0);
  clear_has_vpid();
}
inline ::google::protobuf::uint64 container_info::vpid() const {
  return vpid_;
}
inline void container_info::set_vpid(::google::protobuf::uint64 value) {
  set_has_vpid();
  vpid_ = value;
}

// required string root = 4;
inline bool container_info::has_root() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void container_info::set_has_root() {
  _has_bits_[0] |= 0x00000008u;
}
inline void container_info::clear_has_root() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void container_info::clear_root() {
  if (root_ != &::google::protobuf::internal::kEmptyString) {
    root_->clear();
  }
  clear_has_root();
}
inline const ::std::string& container_info::root() const {
  return *root_;
}
inline void container_info::set_root(const ::std::string& value) {
  set_has_root();
  if (root_ == &::google::protobuf::internal::kEmptyString) {
    root_ = new ::std::string;
  }
  root_->assign(value);
}
inline void container_info::set_root(const char* value) {
  set_has_root();
  if (root_ == &::google::protobuf::internal::kEmptyString) {
    root_ = new ::std::string;
  }
  root_->assign(value);
}
inline void container_info::set_root(const char* value, size_t size) {
  set_has_root();
  if (root_ == &::google::protobuf::internal::kEmptyString) {
    root_ = new ::std::string;
  }
  root_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* container_info::mutable_root() {
  set_has_root();
  if (root_ == &::google::protobuf::internal::kEmptyString) {
    root_ = new ::std::string;
  }
  return root_;
}
inline ::std::string* container_info::release_root() {
  clear_has_root();
  if (root_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = root_;
    root_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}
inline void container_info::set_allocated_root(::std::string* root) {
  if (root_ != &::google::protobuf::internal::kEmptyString) {
    delete root_;
  }
  if (root) {
    set_has_root();
    root_ = root;
  } else {
    clear_has_root();
    root_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  }
}

// -------------------------------------------------------------------

// mounted_fs_request

// repeated .sdc_internal.container_info containers = 1;
inline int mounted_fs_request::containers_size() const {
  return containers_.size();
}
inline void mounted_fs_request::clear_containers() {
  containers_.Clear();
}
inline const ::sdc_internal::container_info& mounted_fs_request::containers(int index) const {
  return containers_.Get(index);
}
inline ::sdc_internal::container_info* mounted_fs_request::mutable_containers(int index) {
  return containers_.Mutable(index);
}
inline ::sdc_internal::container_info* mounted_fs_request::add_containers() {
  return containers_.Add();
}
inline const ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_info >&
mounted_fs_request::containers() const {
  return containers_;
}
inline ::google::protobuf::RepeatedPtrField< ::sdc_internal::container_info >*
mounted_fs_request::mutable_containers() {
  return &containers_;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace sdc_internal

#ifndef SWIG
namespace google {
namespace protobuf {


}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_sdc_5finternal_2eproto__INCLUDED
