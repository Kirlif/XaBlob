class Header:
    def __init__(self, magic, version, entry_count, index_entry_count, index_size):
        self.magic = magic
        self.version = version
        self.entry_count = entry_count
        self.index_entry_count = index_entry_count
        self.index_size = index_size


class IndexEntry:
    def __init__(self, name_hash, descriptor_index, ignore):
        self.name_hash = name_hash
        self.descriptor_index = descriptor_index
        self.ignore = ignore


class EntryDescriptor:
    def __init__(
        self,
        mapping_index,
        data_offset,
        data_size,
        debug_data_offset,
        debug_data_size,
        config_data_offset,
        config_data_size,
    ):
        self.mapping_index = mapping_index
        self.data_offset = data_offset
        self.data_size = data_size
        self.debug_data_offset = debug_data_offset
        self.debug_data_size = debug_data_size
        self.config_data_offset = config_data_offset
        self.config_data_size = config_data_size


class TemporaryItem:
    def __init__(self, name, descriptor, ignored):
        self.name = name
        self.descriptor = descriptor
        self.index_entries = []
        self.ignored = ignored


class AssemblyStoreItem:
    def __init__(self, name, is64bit, hashes, ignore):
        self.name = name
        self.is64bit = is64bit
        self.hashes = hashes
        self.ignore = ignore


class StoreItemV2(AssemblyStoreItem):
    def __init__(self, target_arch, name, is64bit, index_entries, descriptor, ignore):
        super().__init__(name, is64bit, self.index_to_hashes(index_entries), ignore)
        self.data_offset = descriptor.data_offset
        self.data_size = descriptor.data_size
        self.debug_offset = descriptor.debug_data_offset
        self.debug_size = descriptor.debug_data_size
        self.config_offset = descriptor.config_data_offset
        self.config_size = descriptor.config_data_size
        self.mapping_index = descriptor.mapping_index
        self.target_arch = target_arch
        self.is_compressed = None
        self.index_rt_desc_array = None

    @staticmethod
    def index_to_hashes(index_entries):
        return [ie.name_hash for ie in index_entries]
